package manage

import (
	"context"
	"encoding/base64"
	"errors"
	"github.com/hardyos/hardyos/daemon/internal/mail"
	"slices"
	"strings"
	"time"
)

// ---- certificate ----

// CertificateResult says what a certificate run did.
type CertificateResult struct {
	Renewed bool           `json:"renewed"`
	Message string         `json:"message"`
	Cert    *mail.CertInfo `json:"cert,omitempty"`
}

// RenewCertificate gets a Let's Encrypt certificate for the mail server's
// name when there's none, it's self-signed, for another name, or within
// RenewBefore of expiring (always with force).
func (s *Service) RenewCertificate(ctx context.Context, force bool, progress func(float64, string)) (*CertificateResult, error) {
	st, err := s.Store.LoadSettings(ctx)
	if err != nil {
		return nil, err
	}
	if st.TLSMode != "acme" {
		return &CertificateResult{Message: "The certificate isn't from Let's Encrypt (Control Panel › Mail › Certificate)."}, nil
	}
	if st.Pool == "" || st.Hostname == "" {
		return nil, mail.Invalid("set up the mail server first")
	}
	token, err := s.Store.Secret(ctx, SecretCloudflare)
	if err != nil {
		return nil, err
	}
	if token == "" {
		return nil, mail.Invalid("Let's Encrypt needs a Cloudflare API token for the DNS challenge")
	}
	if !force {
		var status mail.Status
		if err := s.Priv.Call(ctx, mail.OpStatus, mail.StatusArgs{Pool: st.Pool}, &status); err == nil && status.Cert != nil {
			c := status.Cert
			if !c.SelfSigned && slices.Contains(c.Names, st.Hostname) && time.Until(c.NotAfter) > RenewBefore {
				return &CertificateResult{Message: "The certificate is valid until " + c.NotAfter.Format("2 Jan 2006") + ".", Cert: c}, nil
			}
		}
	}
	key, err := s.Store.Secret(ctx, SecretACME)
	if err != nil {
		return nil, err
	}
	if key == "" {
		k, err := ACMEAccountKey()
		if err != nil {
			return nil, err
		}
		key = string(k)
		if err := s.Store.SetSecret(ctx, SecretACME, key); err != nil {
			return nil, err
		}
	}
	progress(5, "Making a new key")
	var csr mail.CSRResult
	if err := s.Priv.Call(ctx, mail.OpCSR, mail.CSRArgs{Pool: st.Pool, Names: []string{st.Hostname}}, &csr); err != nil {
		return nil, err
	}
	der, err := base64.StdEncoding.DecodeString(csr.CSR)
	if err != nil {
		return nil, err
	}
	dir := LetsEncrypt
	if st.ACMEStaging {
		dir = LetsEncryptStaging
	}
	iss := &ACMEIssuer{Directory: dir, AccountKey: []byte(key), Email: st.ACMEEmail,
		DNS: CFChallenger{CF: &Cloudflare{Token: token}}, Resolver: s.Resolver, Progress: progress}
	chain, err := iss.Issue(ctx, []string{st.Hostname}, der)
	if err != nil {
		return nil, err
	}
	progress(90, "Installing the certificate")
	var info mail.CertInfo
	if err := s.Priv.Call(ctx, mail.OpInstall, mail.InstallArgs{Pool: st.Pool, Hostname: st.Hostname, Chain: string(chain)}, &info); err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.certTime = time.Time{}
	s.mu.Unlock()
	return &CertificateResult{Renewed: true, Message: "Installed a certificate valid until " + info.NotAfter.Format("2 Jan 2006") + ".", Cert: &info}, nil
}

// UploadCertificate installs a certificate and key an administrator
// uploaded (PEM).
func (s *Service) UploadCertificate(ctx context.Context, chain, key string) (*mail.CertInfo, error) {
	st, err := s.Store.LoadSettings(ctx)
	if err != nil {
		return nil, err
	}
	if st.Pool == "" || st.Hostname == "" {
		return nil, mail.Invalid("set up the mail server first")
	}
	if !strings.Contains(chain, "BEGIN CERTIFICATE") || !strings.Contains(key, "PRIVATE KEY") {
		return nil, mail.Invalid("paste the certificate chain and its private key (PEM)")
	}
	var info mail.CertInfo
	if err := s.Priv.Call(ctx, mail.OpInstall, mail.InstallArgs{Pool: st.Pool, Hostname: st.Hostname, Chain: chain, Key: key}, &info); err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.certTime = time.Time{}
	s.mu.Unlock()
	return &info, nil
}

// ---- Cloudflare ----

// PublishDNS writes a domain's records into Cloudflare.
func (s *Service) PublishDNS(ctx context.Context, name string) ([]SyncResult, error) {
	token, err := s.Store.Secret(ctx, SecretCloudflare)
	if err != nil {
		return nil, err
	}
	if token == "" {
		return nil, mail.Invalid("add a Cloudflare API token first")
	}
	d, err := s.Store.GetDomain(ctx, name)
	if err != nil {
		return nil, err
	}
	if d.DKIMPublic == "" {
		return nil, mail.Invalid("the DKIM key for %s isn't made yet: turn the mail server on (or apply) first", name)
	}
	recs, err := s.DomainRecords(ctx, d)
	if err != nil {
		return nil, err
	}
	var publish []mail.Record
	for _, r := range recs {
		// MTA-STS needs a web server for its policy; autoconfig CNAMEs need
		// a certificate for their names: both are left to the administrator.
		if r.Purpose == "mta-sts" || (r.Purpose == "autoconfig" && r.Type == "CNAME") {
			continue
		}
		publish = append(publish, r)
	}
	return (&Cloudflare{Token: token}).Publish(ctx, publish), nil
}

// VerifyCloudflare checks a token before it's saved.
func VerifyCloudflare(ctx context.Context, token string) error {
	return (&Cloudflare{Token: token}).Verify(ctx)
}

// ---- SES ----

func (s *Service) sesClient(ctx context.Context) (*SESClient, error) {
	st, err := s.Store.LoadSettings(ctx)
	if err != nil {
		return nil, err
	}
	secret, err := s.Store.Secret(ctx, SecretSES)
	if err != nil {
		return nil, err
	}
	if st.SESRegion == "" || st.SESAccessID == "" || secret == "" {
		return nil, mail.Invalid("enter the Amazon SES region, access key ID and secret access key first")
	}
	return &SESClient{Region: st.SESRegion, AccessKey: st.SESAccessID, SecretKey: secret}, nil
}

// SESStatus is the SES account and every domain's identity.
type SESStatus struct {
	Account    *SESAccount             `json:"account,omitempty"`
	Identities map[string]*SESIdentity `json:"identities"`
	Error      string                  `json:"error,omitempty"`
}

// SESState asks SES about the account and the domains.
func (s *Service) SESState(ctx context.Context) (*SESStatus, error) {
	cl, err := s.sesClient(ctx)
	if err != nil {
		return nil, err
	}
	out := &SESStatus{Identities: map[string]*SESIdentity{}}
	if out.Account, err = cl.Account(ctx); err != nil {
		out.Error = err.Error()
		return out, nil
	}
	doms, err := s.Store.Domains(ctx)
	if err != nil {
		return nil, err
	}
	for _, d := range doms {
		id, err := cl.Identity(ctx, d.Name)
		if err != nil {
			out.Error = err.Error()
			continue
		}
		out.Identities[d.Name] = id
		_ = s.Store.SetSES(ctx, d.Name, id.DKIMTokens, id.DKIMStatus, id.MailFromDomain != "")
	}
	return out, nil
}

// SESVerify adds a domain to SES (or reads it) and stores the Easy DKIM
// tokens, so its DNS records list them.
func (s *Service) SESVerify(ctx context.Context, name string) (*SESIdentity, error) {
	if _, err := s.Store.GetDomain(ctx, name); err != nil {
		return nil, err
	}
	cl, err := s.sesClient(ctx)
	if err != nil {
		return nil, err
	}
	st, _ := s.Store.LoadSettings(ctx)
	id, err := cl.Identity(ctx, name)
	if err != nil {
		return nil, err
	}
	if !id.Exists {
		if id, err = cl.CreateIdentity(ctx, name); err != nil {
			return nil, err
		}
	}
	if st.SESMailFrom && id.MailFromDomain == "" {
		if err := cl.SetMailFrom(ctx, name); err != nil {
			return nil, err
		}
		id.MailFromDomain = "bounce." + name
	}
	if err := s.Store.SetSES(ctx, name, id.DKIMTokens, id.DKIMStatus, id.MailFromDomain != ""); err != nil {
		return nil, err
	}
	return id, nil
}

// ---- VPS ----

// VPSScriptFor renders the VPS script with the current settings.
func (s *Service) VPSScriptFor(ctx context.Context) (string, error) {
	st, err := s.Store.LoadSettings(ctx)
	if err != nil {
		return "", err
	}
	doms, err := s.Store.Domains(ctx)
	if err != nil {
		return "", err
	}
	var names []string
	for _, d := range doms {
		names = append(names, d.Name)
	}
	home := ""
	if s.NetBirdAddr != nil {
		home = s.NetBirdAddr(ctx)
	}
	return mail.VPSScript(mail.VPSSetup{Hostname: st.Hostname, HomePeer: home, Domains: names, MaxMessageMB: st.MaxMessageMB})
}

// CheckVPSNow tests the VPS from here (see CheckVPS).
func (s *Service) CheckVPSNow(ctx context.Context) ([]mail.VPSCheck, error) {
	st, err := s.Store.LoadSettings(ctx)
	if err != nil {
		return nil, err
	}
	doms, err := s.Store.Domains(ctx)
	if err != nil {
		return nil, err
	}
	if st.VPSIPv4 == "" || st.Hostname == "" || len(doms) == 0 {
		return nil, mail.Invalid("enter the VPS's public address, the mail server's name and a domain first")
	}
	var status mail.Status
	fp := ""
	if err := s.Priv.Call(ctx, mail.OpStatus, mail.StatusArgs{Pool: st.Pool}, &status); err == nil && status.Cert != nil {
		fp = status.Cert.Fingerprint
	}
	checks := mail.CheckVPS(ctx, nil, st.VPSIPv4, st.Hostname, doms[0].Name, fp)
	// The VPS's NetBird address must be what relayed mail comes from.
	if s.NetBirdAddr != nil && s.NetBirdAddr(ctx) == "" {
		checks = append(checks, mail.VPSCheck{Name: "NetBird", Detail: "this server isn't connected to NetBird (Control Panel › Remote Access)"})
	}
	return checks, nil
}

// ---- notifications through this server ----

// NotifyPassword returns (making it first) the notification sign-in's
// password, for the "HardyOS Mail" notification channel.
func (s *Service) NotifyPassword(ctx context.Context) (string, error) {
	return s.Store.EnsureSecret(ctx, SecretNotify)
}

// ErrMailOff is returned when the mail server isn't on.
var ErrMailOff = errors.New("the mail server is off")
