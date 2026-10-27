package rootauth

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"

	"github.com/hardyos/hardyos/daemon/internal/domain"
)

// kerberosLogin asks this server's own DC (its address inside the host,
// decision 78) for a ticket-granting ticket with the password; the ticket
// is thrown away. Any failure is a wrong password except the DC not
// answering.
func kerberosLogin(ctx context.Context, c *domain.Config, user, password string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	kdc := net.JoinHostPort(c.IP(), "88")
	d := net.Dialer{Timeout: 2 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", kdc)
	if err != nil {
		return ErrDomain
	}
	conn.Close()
	realm := strings.ToUpper(c.Realm)
	cfg := config.New()
	cfg.LibDefaults.DefaultRealm = realm
	cfg.LibDefaults.DNSLookupKDC = false
	cfg.LibDefaults.DNSLookupRealm = false
	cfg.LibDefaults.UDPPreferenceLimit = 1
	cfg.LibDefaults.NoAddresses = true
	cfg.Realms = []config.Realm{{Realm: realm, KDC: []string{kdc}, DefaultDomain: strings.ToLower(c.Domain)}}
	if c.Domain != "" {
		cfg.DomainRealm[strings.ToLower(c.Domain)] = realm
		cfg.DomainRealm["."+strings.ToLower(c.Domain)] = realm
	}
	cl := client.NewWithPassword(user, realm, password, cfg, client.DisablePAFXFAST(true))
	done := make(chan error, 1)
	go func() {
		err := cl.Login()
		cl.Destroy()
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			return ErrWrong
		}
		return nil
	case <-ctx.Done():
		return ErrDomain
	}
}
