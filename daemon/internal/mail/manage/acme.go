package manage

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/hardyos/hardyos/daemon/internal/mail"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
)

// The mail server's certificate (decision 243): Let's Encrypt with the
// DNS-01 challenge answered through Cloudflare. Mail apps connect to the
// VPS's address, which forwards TCP home, so HTTP-01 would have to go
// through the VPS; DNS-01 needs nothing there and works while home is
// unreachable from the internet. The key is made by root (CSR) and never
// leaves it: hardyd only speaks ACME with Let's Encrypt and Cloudflare.

// ACME directories.
const (
	LetsEncrypt        = "https://acme-v02.api.letsencrypt.org/directory"
	LetsEncryptStaging = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

// RenewBefore is how long before expiry a certificate is renewed.
const RenewBefore = 30 * 24 * time.Hour

// ACMEAccountKey makes a new account key (PEM).
func ACMEAccountKey() ([]byte, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

func parseAccountKey(p []byte) (crypto.Signer, error) {
	blk, _ := pem.Decode(p)
	if blk == nil {
		return nil, errors.New("the ACME account key isn't PEM")
	}
	return x509.ParseECPrivateKey(blk.Bytes)
}

// DNSChallenger publishes and removes the _acme-challenge TXT record.
type DNSChallenger interface {
	Present(ctx context.Context, name, value string) (cleanup func(), err error)
}

// CFChallenger answers DNS-01 through Cloudflare.
type CFChallenger struct{ CF *Cloudflare }

// Present adds the TXT record and returns its removal.
func (c CFChallenger) Present(ctx context.Context, name, value string) (func(), error) {
	zid, _, err := c.CF.Zone(ctx, name)
	if err != nil {
		return nil, err
	}
	rec, err := c.CF.Create(ctx, zid, CFRecord{Type: "TXT", Name: name, Content: value, TTL: 60, Comment: CFComment + " acme"})
	if err != nil {
		return nil, err
	}
	return func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		_ = c.CF.Delete(ctx, zid, rec.ID)
	}, nil
}

// ACMEIssuer obtains certificates.
type ACMEIssuer struct {
	Directory  string
	AccountKey []byte // PEM
	Email      string
	DNS        DNSChallenger
	// Resolver confirms the TXT record is visible before asking Let's
	// Encrypt to look (default: PublicResolver).
	Resolver mail.Resolver
	// Progress reports steps (jobs).
	Progress func(pct float64, msg string)
}

func (a *ACMEIssuer) progress(p float64, m string) {
	if a.Progress != nil {
		a.Progress(p, m)
	}
}

// Issue gets a certificate for csr (DER) naming names, returning the PEM
// chain.
func (a *ACMEIssuer) Issue(ctx context.Context, names []string, csr []byte) ([]byte, error) {
	key, err := parseAccountKey(a.AccountKey)
	if err != nil {
		return nil, err
	}
	dir := a.Directory
	if dir == "" {
		dir = LetsEncrypt
	}
	cl := &acme.Client{Key: key, DirectoryURL: dir, UserAgent: "HardyOS"}
	acct := &acme.Account{}
	if a.Email != "" {
		acct.Contact = []string{"mailto:" + a.Email}
	}
	a.progress(10, "Signing in to Let's Encrypt")
	if _, err := cl.Register(ctx, acct, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return nil, fmt.Errorf("Let's Encrypt account: %w", err)
	}
	var ids []acme.AuthzID
	for _, n := range names {
		ids = append(ids, acme.AuthzID{Type: "dns", Value: n})
	}
	order, err := cl.AuthorizeOrder(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("Let's Encrypt order: %w", err)
	}
	res := a.Resolver
	if res == nil {
		res = mail.PublicResolver()
	}
	for i, u := range order.AuthzURLs {
		z, err := cl.GetAuthorization(ctx, u)
		if err != nil {
			return nil, err
		}
		if z.Status == acme.StatusValid {
			continue
		}
		var chal *acme.Challenge
		for _, c := range z.Challenges {
			if c.Type == "dns-01" {
				chal = c
			}
		}
		if chal == nil {
			return nil, errors.New("Let's Encrypt offered no DNS challenge")
		}
		val, err := cl.DNS01ChallengeRecord(chal.Token)
		if err != nil {
			return nil, err
		}
		name := "_acme-challenge." + z.Identifier.Value
		a.progress(20+float64(i)*10, "Publishing "+name)
		cleanup, err := a.DNS.Present(ctx, name, val)
		if err != nil {
			return nil, fmt.Errorf("publishing the DNS challenge: %w", err)
		}
		err = func() error {
			defer cleanup()
			a.progress(40, "Waiting for DNS to show the challenge")
			if err := waitTXT(ctx, res, name, val, 3*time.Minute); err != nil {
				return err
			}
			if _, err := cl.Accept(ctx, chal); err != nil {
				return err
			}
			a.progress(60, "Let's Encrypt is checking")
			if _, err := cl.WaitAuthorization(ctx, z.URI); err != nil {
				return fmt.Errorf("Let's Encrypt couldn't verify %s: %w", z.Identifier.Value, err)
			}
			return nil
		}()
		if err != nil {
			return nil, err
		}
	}
	a.progress(80, "Getting the certificate")
	order, err = cl.WaitOrder(ctx, order.URI)
	if err != nil {
		return nil, err
	}
	ders, _, err := cl.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return nil, fmt.Errorf("Let's Encrypt certificate: %w", err)
	}
	var b strings.Builder
	for _, d := range ders {
		b.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d}))
	}
	return []byte(b.String()), nil
}

func waitTXT(ctx context.Context, r mail.Resolver, name, val string, max time.Duration) error {
	deadline := time.Now().Add(max)
	for {
		txts, _ := r.LookupTXT(ctx, name)
		for _, t := range txts {
			if t == val {
				// Give every authoritative server a moment too.
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(10 * time.Second):
				}
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the challenge record %s didn't show up in public DNS within %s", name, max)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}
