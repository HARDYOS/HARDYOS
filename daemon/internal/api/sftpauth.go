package api

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/sftpauth"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

// SFTP sign-in questions from sshd's PAM stack (decisions 514-516): the
// rule is WebDAV's (decision 445). An app password with the sftp scope
// always works; the account's own password (checked by pam_winbind) only
// from home by decision 441's address rule and only without two-factor
// sign-in, asked before winbind and again after it said yes.

// sftpPeerUID is how the socket's other end is identified (tests replace
// it).
var sftpPeerUID = sftpauth.PeerUID

// RunSFTPAuth answers sshd's PAM questions on ln (hardyd-sftp-auth.socket)
// until ctx ends.
func (s *Server) RunSFTPAuth(ctx context.Context, ln net.Listener) {
	if ln == nil {
		return
	}
	if ln.Addr().Network() != "unix" {
		_ = ln.Close()
		s.log.Warn("sftp sign-in socket isn't a Unix socket")
		return
	}
	if err := sftpauth.Serve(ctx, ln, s.sftpAnswer, sftpPeerUID); err != nil {
		s.log.Warn("sftp sign-in socket", "err", err)
	}
}

// sftpLimited notes refused requests per key, so a script can't fill the
// audit log with "rate limited" entries.
type sftpLimited struct {
	mu   sync.Mutex
	last map[string]time.Time
}

func (l *sftpLimited) first(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.last == nil {
		l.last = map[string]time.Time{}
	}
	now := time.Now()
	if t, ok := l.last[key]; ok && now.Sub(t) < time.Minute {
		return false
	}
	if len(l.last) > 4096 {
		l.last = map[string]time.Time{}
	}
	l.last[key] = now
	return true
}

func (s *Server) sftpRecord(ctx context.Context, u *auth.User, target, ip string, outcome audit.Outcome, detail string) {
	e := audit.Entry{Action: "sftp.login", Target: target, Outcome: outcome, Detail: detail, IP: ip, Actor: "anonymous"}
	if u != nil {
		id := u.ID
		e.ActorID, e.Actor = &id, u.Username
	}
	if err := s.audit.Record(context.WithoutCancel(ctx), e); err != nil {
		s.log.Error("audit write failed", "action", e.Action, "err", err)
	}
}

func sftpNo(reason string) sftpauth.Answer { return sftpauth.Answer{Reason: reason} }

var sftpYes = sftpauth.Answer{OK: true}

// sftpIPKey is the address an SFTP sign-in's failures count against: from
// outside an IPv6 address counts per /64 (one household or one attacker
// has the whole /64), at home the address itself.
func sftpIPKey(a netip.Addr, outside bool) string {
	if !a.IsValid() {
		return "ip:"
	}
	if outside && a.Is6() {
		p, _ := a.Prefix(64)
		return "ip:" + p.String()
	}
	return "ip:" + a.String()
}

// sftpAudit writes an SFTP audit entry off the answer path, and refusals
// at most once a minute per kind, address and name (sshd and scripts can
// retry fast).
func (s *Server) sftpAudit(ctx context.Context, u *auth.User, target, ip string, outcome audit.Outcome, detail, throttle string) {
	if throttle != "" && !s.sftpNotes.first(throttle) {
		return
	}
	ctx = context.WithoutCancel(ctx)
	s.sftpAudits.Add(1)
	go func() {
		defer s.sftpAudits.Done()
		s.sftpRecord(ctx, u, target, ip, outcome, detail)
	}()
}

// sftpAnswer decides one question (decisions 514, 519).
func (s *Server) sftpAnswer(ctx context.Context, req sftpauth.Request) sftpauth.Answer {
	if s.signin == nil || s.signin.Domain == nil {
		return sftpNo("this server has no domain")
	}
	a := req.Addr()
	ip := ""
	if a.IsValid() {
		ip = a.String()
	}
	// No readable address, this server's own, Docker's, the router's
	// (even trusted: own passwords stay refused from it), the internet:
	// outside.
	outside := !a.IsValid() || !s.insideAddr(a)
	ipKey := sftpIPKey(a, outside)
	userKey := s.signin.LimitKey(ctx, req.User)
	throttle := func(kind string) string { return kind + "|" + ipKey + "|" + userKey }
	switch req.Op {
	case sftpauth.OpApp:
		// A right app password always works, whatever the rate limits say
		// (they count failures); a wrong one is decided by the next step.
		row, err := s.signin.DomainUser(ctx, req.User)
		if err != nil || row == nil {
			return sftpNo("not an app password")
		}
		ok, err := s.appPw.Check(ctx, row.ID, req.Password, auth.ScopeSFTP, ip)
		if err != nil || !ok {
			return sftpNo("not an app password with the sftp scope")
		}
		if err := s.signin.CheckDomainAccount(ctx, row); err != nil {
			s.cfg.Limiter.Fail(ipKey)
			s.sftpAudit(ctx, row, row.Username, ip, audit.Failure, "app password: "+err.Error(), throttle("account"))
			return sftpNo(err.Error())
		}
		s.cfg.Limiter.Succeed(ipKey)
		s.cfg.Limiter.Succeed(userKey)
		s.sftpAudit(ctx, row, row.Username, ip, audit.Success, "sftp, app password"+outsideNote(outside), "")
		return sftpYes
	case sftpauth.OpOwn:
		row, err := s.signin.DomainUser(ctx, req.User)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return sftpNo("the domain isn't answering")
		}
		allowed := true
		if s.mfa != nil {
			if allowed, err = s.mfa.PasswordAllowed(ctx, row, outside); err != nil {
				return sftpNo("two-factor state unreadable")
			}
		}
		if !allowed {
			// The password isn't checked: counted against the address
			// only, so an old client can't lock its owner out.
			s.cfg.Limiter.Fail(ipKey)
			s.sftpAudit(ctx, row, req.User, ip, audit.Failure, errAppPasswordRequired.Error()+outsideNote(outside), throttle("app-password"))
			return sftpNo("use an app password")
		}
		// The password goes to winbind: an attempt is reserved for the
		// address and the account in one step (counted until it works).
		for _, k := range []string{ipKey, userKey} {
			if ok, _ := s.cfg.Limiter.Try(k); !ok {
				s.sftpAudit(ctx, row, req.User, ip, audit.Denied, "rate limited", throttle("limited"))
				return sftpNo("rate limited")
			}
		}
		return sftpYes
	case sftpauth.OpAfter:
		// winbind said yes: the row is made or brought up to date from the
		// directory like a desktop sign-in, and the rule checked on it.
		u, err := s.signin.SyncDomainAccount(ctx, req.User)
		if err != nil {
			s.sftpAudit(ctx, nil, req.User, ip, audit.Failure, "sftp: "+err.Error(), throttle("account"))
			return sftpNo(err.Error())
		}
		if s.mfa != nil {
			allowed, err := s.mfa.PasswordAllowed(ctx, u, outside)
			if err != nil {
				return sftpNo("two-factor state unreadable")
			}
			if !allowed {
				s.sftpAudit(ctx, u, u.Username, ip, audit.Failure, errAppPasswordRequired.Error()+outsideNote(outside), throttle("app-password"))
				return sftpNo("use an app password")
			}
		}
		s.cfg.Limiter.Succeed(ipKey)
		s.cfg.Limiter.Succeed(userKey)
		s.sftpAudit(ctx, u, u.Username, ip, audit.Success, "sftp", "")
		return sftpYes
	case sftpauth.OpFail:
		// Counted when the own-password step reserved the attempt.
		s.sftpAudit(ctx, nil, req.User, ip, audit.Failure, "sftp: wrong password"+outsideNote(outside), throttle("wrong"))
		return sftpYes
	}
	return sftpNo("unknown op")
}

// endSFTPSessions ends a domain account's SFTP sessions that started
// before before (all when zero), off the request path (decision 519).
func (s *Server) endSFTPSessions(ctx context.Context, u *auth.User, before time.Time, why string) {
	if u == nil || u.Source != auth.SourceDomain || u.Principal == "" || s.cfg.Priv == nil {
		return
	}
	ctx = context.WithoutCancel(ctx)
	go func() {
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		var res priv.SFTPEndResult
		if err := s.cfg.Priv.Call(ctx, priv.OpFilesSFTPEnd, priv.SFTPEndArgs{Account: u.Principal, Before: before}, &res); err != nil {
			s.log.Debug("sftp: ending sessions", "user", u.Username, "err", err)
			return
		}
		if res.Ended > 0 {
			s.recordSystem(ctx, "sftp.session.end", u.Username, fmt.Sprintf("%s; %d SFTP sessions ended", why, res.Ended))
		}
	}()
}
