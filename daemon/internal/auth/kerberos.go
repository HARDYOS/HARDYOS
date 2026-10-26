package auth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/krberror"
)

// KerberosChecker verifies a domain password with a Kerberos AS exchange
// (asking a domain controller for a ticket-granting ticket), in pure Go.
// Nothing is kept: the ticket is thrown away.
//
// An AS exchange proves only that whoever answered knew a key for the
// password typed, and an impostor answering for a DC's address can make one
// up for any password. So only this server's own DC is asked
// (DomainInfo.LocalKDC, reached inside the host), never a partner DC on the
// LAN, even when the local one is down.
type KerberosChecker struct {
	// Timeout bounds the whole check (default 10 s).
	Timeout time.Duration
	// ProbeTimeout bounds finding out whether the local DC accepts a
	// connection at all (default 2 s), so a stopped DC answers quickly.
	ProbeTimeout time.Duration
	// Port is the KDC port (default 88; tests).
	Port int
}

// CheckPassword implements PasswordChecker.
func (k KerberosChecker) CheckPassword(ctx context.Context, d DomainInfo, username, password string) error {
	if d.Realm == "" {
		return ErrDomainUnavailable
	}
	if d.LocalKDC == "" {
		return ErrNoLocalDC
	}
	timeout := k.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	kdc := net.JoinHostPort(d.LocalKDC, k.port())
	if !k.reachable(ctx, kdc) {
		return ErrDomainUnavailable
	}
	cfg := krbConfig(d, kdc)
	cl := client.NewWithPassword(username, strings.ToUpper(d.Realm), password, cfg, client.DisablePAFXFAST(true))
	done := make(chan error, 1)
	go func() {
		err := cl.Login()
		cl.Destroy()
		done <- err
	}()
	select {
	case err := <-done:
		return MapKerberosError(err)
	case <-ctx.Done():
		// The library has its own 5 s deadlines per connection; the goroutine ends by itself.
		return ErrDomainUnavailable
	}
}

func (k KerberosChecker) port() string {
	if k.Port > 0 {
		return strconv.Itoa(k.Port)
	}
	return "88"
}

// reachable reports whether the KDC accepts a TCP connection.
func (k KerberosChecker) reachable(ctx context.Context, addr string) bool {
	pt := k.ProbeTimeout
	if pt <= 0 {
		pt = 2 * time.Second
	}
	pctx, cancel := context.WithTimeout(ctx, pt)
	defer cancel()
	var dl net.Dialer
	c, err := dl.DialContext(pctx, "tcp", addr)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// krbConfig is a krb5.conf for one realm with one fixed KDC: no DNS lookups,
// TCP only (AD tickets with group lists outgrow UDP).
func krbConfig(d DomainInfo, kdc string) *config.Config {
	realm := strings.ToUpper(d.Realm)
	cfg := config.New()
	cfg.LibDefaults.DefaultRealm = realm
	cfg.LibDefaults.DNSLookupKDC = false
	cfg.LibDefaults.DNSLookupRealm = false
	cfg.LibDefaults.UDPPreferenceLimit = 1
	cfg.LibDefaults.NoAddresses = true
	cfg.Realms = []config.Realm{{Realm: realm, KDC: []string{kdc}, DefaultDomain: strings.ToLower(d.DNS)}}
	if d.DNS != "" {
		cfg.DomainRealm[strings.ToLower(d.DNS)] = realm
		cfg.DomainRealm["."+strings.ToLower(d.DNS)] = realm
	}
	return cfg
}

var krbCodeRE = regexp.MustCompile(`KRB Error: \((\d+)\)`)

// MapKerberosError turns a gokrb5 error into the sign-in errors.
func MapKerberosError(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if m := krbCodeRE.FindStringSubmatch(msg); m != nil {
		code, _ := strconv.Atoi(m[1])
		switch int32(code) {
		case errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN, errorcode.KDC_ERR_PREAUTH_FAILED, errorcode.KRB_AP_ERR_BAD_INTEGRITY:
			return ErrBadCredentials
		case errorcode.KDC_ERR_CLIENT_REVOKED, errorcode.KDC_ERR_POLICY:
			return ErrAccountRevoked
		case errorcode.KDC_ERR_KEY_EXPIRED:
			return ErrPasswordExpired
		case errorcode.KRB_AP_ERR_SKEW:
			return ErrClockSkew
		}
		return fmt.Errorf("the domain controller refused the sign-in: %s", msg)
	}
	var ke krberror.Krberror
	if errors.As(err, &ke) {
		switch ke.RootCause {
		case krberror.NetworkingError:
			return ErrDomainUnavailable
		case krberror.DecryptingError, krberror.KRBMsgError, krberror.ChksumError:
			// The KDC's answer didn't decrypt with this password: a wrong
			// password on an account that doesn't need pre-authentication.
			return ErrBadCredentials
		}
	}
	if strings.Contains(msg, "communication error") || strings.Contains(msg, "failed to communicate") || strings.Contains(msg, "error sending to a KDC") {
		return ErrDomainUnavailable
	}
	return fmt.Errorf("kerberos: %s", msg)
}
