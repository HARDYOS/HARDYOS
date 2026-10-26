package auth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/krberror"
)

// KerberosChecker verifies a domain password with a Kerberos AS exchange
// (asking a domain controller for a ticket-granting ticket), in pure Go.
// Nothing is kept: the ticket is thrown away.
type KerberosChecker struct {
	// Timeout bounds the whole check (default 10 s).
	Timeout time.Duration
	// ProbeTimeout bounds finding which domain controllers answer (default
	// 2 s). Unreachable ones are left out, so the Kerberos library's own
	// per-server timeouts never add up.
	ProbeTimeout time.Duration
	// Port is the KDC port (default 88; tests).
	Port int
}

// CheckPassword implements PasswordChecker.
func (k KerberosChecker) CheckPassword(ctx context.Context, d DomainInfo, username, password string) error {
	if d.Realm == "" || len(d.KDCs) == 0 {
		return ErrDomainUnavailable
	}
	timeout := k.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	kdcs := k.reachable(ctx, d.KDCs)
	if len(kdcs) == 0 {
		return ErrDomainUnavailable
	}
	cfg := krbConfig(d, kdcs)
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

// reachable returns the KDCs that accept a TCP connection, in their original
// order (this server's own DC first).
func (k KerberosChecker) reachable(ctx context.Context, kdcs []string) []string {
	pt := k.ProbeTimeout
	if pt <= 0 {
		pt = 2 * time.Second
	}
	ok := make([]bool, len(kdcs))
	var wg sync.WaitGroup
	for i, h := range kdcs {
		wg.Add(1)
		go func(i int, addr string) {
			defer wg.Done()
			pctx, cancel := context.WithTimeout(ctx, pt)
			defer cancel()
			var dl net.Dialer
			c, err := dl.DialContext(pctx, "tcp", addr)
			if err == nil {
				c.Close()
				ok[i] = true
			}
		}(i, net.JoinHostPort(h, k.port()))
	}
	wg.Wait()
	var out []string
	for i, h := range kdcs {
		if ok[i] {
			out = append(out, net.JoinHostPort(h, k.port()))
		}
	}
	return out
}

// krbConfig is a krb5.conf for one realm with fixed KDCs: no DNS lookups,
// TCP only (AD tickets with group lists outgrow UDP).
func krbConfig(d DomainInfo, kdcs []string) *config.Config {
	realm := strings.ToUpper(d.Realm)
	cfg := config.New()
	cfg.LibDefaults.DefaultRealm = realm
	cfg.LibDefaults.DNSLookupKDC = false
	cfg.LibDefaults.DNSLookupRealm = false
	cfg.LibDefaults.UDPPreferenceLimit = 1
	cfg.LibDefaults.NoAddresses = true
	cfg.Realms = []config.Realm{{Realm: realm, KDC: kdcs, DefaultDomain: strings.ToLower(d.DNS)}}
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
