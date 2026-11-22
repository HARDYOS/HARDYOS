package hostnames

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/hardyos/hardyos/daemon/internal/cfdns"
)

// ACME directories.
const (
	LetsEncrypt        = "https://acme-v02.api.letsencrypt.org/directory"
	LetsEncryptStaging = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

// TXTResolver looks a TXT record up in public DNS.
type TXTResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// Issuer gets a certificate from an ACME server with the DNS-01 challenge
// answered through root's DNS operations (decision 455). hardyd speaks ACME;
// the Cloudflare token never leaves hardyd-priv.
type Issuer struct {
	Directory  string
	AccountKey crypto.Signer
	Email      string
	DNS        DNS
	// Resolver confirms the challenge is visible before Let's Encrypt is
	// asked to look; nil skips the wait (tests with a fake ACME server).
	Resolver TXTResolver
	// Settle is the extra wait after the record shows up (every
	// authoritative server gets it; default 10 s).
	Settle time.Duration
	// WaitTXT bounds waiting for the record (default 3 minutes).
	WaitTXT  time.Duration
	Progress func(pct float64, msg string)
}

func (a *Issuer) progress(p float64, m string) {
	if a.Progress != nil {
		a.Progress(p, m)
	}
}

// NewKey makes a P-256 key.
func NewKey() (*ecdsa.PrivateKey, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }

// CSR makes a certificate request for names with key.
func CSR(key crypto.Signer, names []string) ([]byte, error) {
	return x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: names[0]},
		DNSNames: names,
	}, key)
}

// Issue gets a certificate for csr (DER) naming names and returns the PEM
// chain.
func (a *Issuer) Issue(ctx context.Context, names []string, csr []byte) ([]byte, error) {
	if a.AccountKey == nil || a.DNS == nil {
		return nil, errors.New("the issuer isn't set up")
	}
	dir := a.Directory
	if dir == "" {
		dir = LetsEncrypt
	}
	cl := &acme.Client{Key: a.AccountKey, DirectoryURL: dir, UserAgent: "HardyOS"}
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
		name := cfdns.ChallengeName(z.Identifier.Value)
		a.progress(20+float64(i)*10, "Publishing "+name+" in Cloudflare")
		id, err := a.DNS.Present(ctx, name, val)
		if err != nil {
			return nil, fmt.Errorf("publishing the DNS challenge: %w", err)
		}
		err = func() error {
			defer func() {
				cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
				defer cancel()
				_ = a.DNS.Cleanup(cctx, id)
			}()
			if a.Resolver != nil {
				a.progress(40, "Waiting for public DNS to show the challenge")
				if err := a.waitTXT(ctx, name, val); err != nil {
					return err
				}
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

func (a *Issuer) waitTXT(ctx context.Context, name, val string) error {
	max := a.WaitTXT
	if max == 0 {
		max = 3 * time.Minute
	}
	settle := a.Settle
	if settle == 0 {
		settle = 10 * time.Second
	}
	deadline := time.Now().Add(max)
	for {
		txts, _ := a.Resolver.LookupTXT(ctx, name)
		for _, t := range txts {
			if t == val {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(settle):
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
		case <-time.After(2 * time.Second):
		}
	}
}
