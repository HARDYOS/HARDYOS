package api

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/auth"
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

// sftpAnswer decides one question.
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
	ipKey := "ip:" + ip
	userKey := s.signin.LimitKey(ctx, req.User)
	limited := func() bool {
		for _, k := range []string{ipKey, userKey} {
			if ok, _ := s.cfg.Limiter.Allowed(k); !ok {
				if s.sftpNotes.first(k) {
					s.sftpRecord(ctx, nil, req.User, ip, audit.Denied, "rate limited")
				}
				return true
			}
		}
		return false
	}
	row, err := s.signin.DomainUser(ctx, req.User)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return sftpNo("the domain isn't answering")
	}
	switch req.Op {
	case sftpauth.OpApp:
		if row == nil || limited() {
			return sftpNo("not an app password")
		}
		ok, err := s.appPw.Check(ctx, row.ID, req.Password, auth.ScopeSFTP, ip)
		if err != nil || !ok {
			// Not counted here: the own-password step decides (refused
			// from outside, counted against the address).
			return sftpNo("not an app password with the sftp scope")
		}
		if err := s.signin.CheckDomainAccount(ctx, row); err != nil {
			s.cfg.Limiter.Fail(ipKey)
			s.sftpRecord(ctx, row, req.User, ip, audit.Failure, "app password: "+err.Error())
			return sftpNo(err.Error())
		}
		s.cfg.Limiter.Succeed(ipKey)
		s.cfg.Limiter.Succeed(userKey)
		s.sftpRecord(ctx, row, row.Username, ip, audit.Success, "sftp, app password"+outsideNote(outside))
		return sftpYes
	case sftpauth.OpOwn, sftpauth.OpAfter:
		if limited() {
			return sftpNo("rate limited")
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
			s.sftpRecord(ctx, row, req.User, ip, audit.Failure, errAppPasswordRequired.Error()+outsideNote(outside))
			return sftpNo("use an app password")
		}
		if req.Op == sftpauth.OpAfter {
			s.cfg.Limiter.Succeed(ipKey)
			s.cfg.Limiter.Succeed(userKey)
			name := req.User
			if row != nil {
				name = row.Username
			}
			s.sftpRecord(ctx, row, name, ip, audit.Success, "sftp")
		}
		return sftpYes
	case sftpauth.OpFail:
		s.cfg.Limiter.Fail(ipKey)
		s.cfg.Limiter.Fail(userKey)
		s.sftpRecord(ctx, nil, req.User, ip, audit.Failure, "sftp: wrong password"+outsideNote(outside))
		return sftpYes
	}
	return sftpNo("unknown op")
}
