package manage

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/hardyos/hardyos/daemon/internal/mail"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/notify"
)

// Amazon SES (decision 234): all outgoing mail goes through SES's SMTP
// interface. One IAM access key does both jobs: its SMTP password is
// derived from the secret key (AWS's documented conversion), and the SES
// API v2 is asked about the domains (verification, Easy DKIM tokens,
// whether the account is still in the sandbox). The secret key is sealed
// in hardyd's database and only the derived SMTP password reaches root.

var regionRE = regexp.MustCompile(`^[a-z]{2}(-gov)?-[a-z]+-[0-9]$`)

// ValidRegion reports whether r looks like an AWS region.
func ValidRegion(r string) bool { return regionRE.MatchString(r) }

// SESSMTPHost is the SMTP endpoint of a region.
func SESSMTPHost(region string) string { return "email-smtp." + region + ".amazonaws.com" }

func hmac256(key []byte, msg string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(msg))
	return m.Sum(nil)
}

// SESSMTPPassword converts an IAM secret access key into the SES SMTP
// password for a region (version 4 of AWS's conversion).
func SESSMTPPassword(secretKey, region string) string {
	k := hmac256([]byte("AWS4"+secretKey), "11111111")
	k = hmac256(k, region)
	k = hmac256(k, "ses")
	k = hmac256(k, "aws4_request")
	k = hmac256(k, "SendRawEmail")
	return base64.StdEncoding.EncodeToString(append([]byte{0x04}, k...))
}

// SESClient talks to the SES API v2.
type SESClient struct {
	Region, AccessKey, SecretKey string
	// HTTP and Endpoint are for tests (default: a guarded client and
	// https://email.<region>.amazonaws.com).
	HTTP     *http.Client
	Endpoint string
	Now      func() time.Time
}

// SESIdentity is a domain's state in SES.
type SESIdentity struct {
	Exists           bool     `json:"exists"`
	VerifiedSending  bool     `json:"verifiedForSending"`
	DKIMStatus       string   `json:"dkimStatus"` // PENDING, SUCCESS, FAILED, TEMPORARY_FAILURE, NOT_STARTED
	DKIMTokens       []string `json:"dkimTokens"`
	MailFromDomain   string   `json:"mailFromDomain"`
	MailFromStatus   string   `json:"mailFromStatus"`
	ProductionAccess *bool    `json:"productionAccess,omitempty"`
}

// SESError is an answer from SES other than success.
type SESError struct {
	Status int
	Type   string
	Msg    string
}

func (e *SESError) Error() string {
	if e.Type != "" {
		return fmt.Sprintf("Amazon SES: %s: %s", e.Type, e.Msg)
	}
	return fmt.Sprintf("Amazon SES answered %d: %s", e.Status, e.Msg)
}

func (c *SESClient) do(ctx context.Context, method, path string, body any, out any) error {
	var b []byte
	if body != nil {
		b, _ = json.Marshal(body)
	}
	ep := c.Endpoint
	if ep == "" {
		if !ValidRegion(c.Region) {
			return mail.Invalid("the AWS region %q isn't valid", c.Region)
		}
		ep = "https://email." + c.Region + ".amazonaws.com"
	}
	req, err := http.NewRequestWithContext(ctx, method, ep+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	notify.SignAWS(req, b, c.AccessKey, c.SecretKey, c.Region, "ses", now())
	hc := c.HTTP
	if hc == nil {
		hc = notify.GuardedClient(false)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("Amazon SES: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if resp.StatusCode/100 != 2 {
		var e struct {
			Message string `json:"message"`
			Type    string `json:"__type"`
		}
		_ = json.Unmarshal(raw, &e)
		t := resp.Header.Get("x-amzn-ErrorType")
		if t == "" {
			t = e.Type
		}
		return &SESError{Status: resp.StatusCode, Type: mail.ClipText(t, 80), Msg: mail.ClipText(e.Message, 300)}
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// Identity reads a domain's state; Exists is false when SES doesn't know
// it yet.
func (c *SESClient) Identity(ctx context.Context, domain string) (*SESIdentity, error) {
	var r struct {
		VerifiedForSendingStatus bool `json:"VerifiedForSendingStatus"`
		DkimAttributes           struct {
			Status string   `json:"Status"`
			Tokens []string `json:"Tokens"`
		} `json:"DkimAttributes"`
		MailFromAttributes struct {
			MailFromDomain       string `json:"MailFromDomain"`
			MailFromDomainStatus string `json:"MailFromDomainStatus"`
		} `json:"MailFromAttributes"`
	}
	err := c.do(ctx, http.MethodGet, "/v2/email/identities/"+url.PathEscape(domain), nil, &r)
	if se, ok := err.(*SESError); ok && se.Status == http.StatusNotFound {
		return &SESIdentity{DKIMTokens: []string{}}, nil
	}
	if err != nil {
		return nil, err
	}
	id := &SESIdentity{Exists: true, VerifiedSending: r.VerifiedForSendingStatus, DKIMStatus: r.DkimAttributes.Status,
		DKIMTokens: r.DkimAttributes.Tokens, MailFromDomain: r.MailFromAttributes.MailFromDomain,
		MailFromStatus: r.MailFromAttributes.MailFromDomainStatus}
	if id.DKIMTokens == nil {
		id.DKIMTokens = []string{}
	}
	return id, nil
}

// CreateIdentity adds a domain to SES (Easy DKIM) and returns its tokens.
func (c *SESClient) CreateIdentity(ctx context.Context, domain string) (*SESIdentity, error) {
	var r struct {
		VerifiedForSendingStatus bool `json:"VerifiedForSendingStatus"`
		DkimAttributes           struct {
			Status string   `json:"Status"`
			Tokens []string `json:"Tokens"`
		} `json:"DkimAttributes"`
	}
	if err := c.do(ctx, http.MethodPost, "/v2/email/identities", map[string]string{"EmailIdentity": domain}, &r); err != nil {
		return nil, err
	}
	return &SESIdentity{Exists: true, VerifiedSending: r.VerifiedForSendingStatus, DKIMStatus: r.DkimAttributes.Status,
		DKIMTokens: r.DkimAttributes.Tokens}, nil
}

// SetMailFrom sets the domain's custom MAIL FROM (bounce.<domain>).
func (c *SESClient) SetMailFrom(ctx context.Context, domain string) error {
	return c.do(ctx, http.MethodPut, "/v2/email/identities/"+url.PathEscape(domain)+"/mail-from",
		map[string]string{"MailFromDomain": "bounce." + domain, "BehaviorOnMxFailure": "USE_DEFAULT_VALUE"}, nil)
}

// SESAccount is the sending account's state.
type SESAccount struct {
	ProductionAccess bool   `json:"productionAccess"`
	SendingEnabled   bool   `json:"sendingEnabled"`
	Max24Hour        int64  `json:"max24HourSend"`
	SentLast24Hours  int64  `json:"sentLast24Hours"`
	Enforcement      string `json:"enforcementStatus"`
}

// Account reads whether the account may send to anyone (out of the
// sandbox) and its quota.
func (c *SESClient) Account(ctx context.Context) (*SESAccount, error) {
	var r struct {
		ProductionAccessEnabled bool   `json:"ProductionAccessEnabled"`
		SendingEnabled          bool   `json:"SendingEnabled"`
		EnforcementStatus       string `json:"EnforcementStatus"`
		SendQuota               struct {
			Max24HourSend   float64 `json:"Max24HourSend"`
			SentLast24Hours float64 `json:"SentLast24Hours"`
		} `json:"SendQuota"`
	}
	if err := c.do(ctx, http.MethodGet, "/v2/email/account", nil, &r); err != nil {
		return nil, err
	}
	return &SESAccount{ProductionAccess: r.ProductionAccessEnabled, SendingEnabled: r.SendingEnabled,
		Max24Hour: int64(r.SendQuota.Max24HourSend), SentLast24Hours: int64(r.SendQuota.SentLast24Hours),
		Enforcement: r.EnforcementStatus}, nil
}
