package notify

// Amazon SES: two ways in. Its SMTP interface works through the SMTP
// channel (email-smtp.<region>.amazonaws.com:587 with SES SMTP credentials).
// The SES channel uses the SES API v2 (SendEmail) over HTTPS, signed with
// Signature Version 4 using an IAM access key: no SMTP credentials to
// derive, outbound port 443 only (many ISPs block 25/587), and an IAM
// policy can allow ses:SendEmail and nothing else. SigV4 is implemented
// here (a few dozen lines, checked against AWS's published test vectors)
// rather than pulling in the AWS SDK.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/mail"
	"net/url"
	"sort"
	"strings"
	"time"
)

// sigV4 signs requests with AWS Signature Version 4.
type sigV4 struct {
	AccessKey, SecretKey, Region, Service string
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// uriEncode is AWS's URI encoding: everything but A-Z a-z 0-9 - _ . ~ is
// percent-encoded (upper-case hex); "/" too unless keepSlash.
func uriEncode(s string, keepSlash bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		case c == '/' && keepSlash:
			b.WriteByte(c)
		default:
			b.WriteString("%" + strings.ToUpper(hex.EncodeToString([]byte{c})))
		}
	}
	return b.String()
}

// signingKey derives the key for one day, region and service.
func (s sigV4) signingKey(date string) []byte {
	k := hmacSHA256([]byte("AWS4"+s.SecretKey), date)
	k = hmacSHA256(k, s.Region)
	k = hmacSHA256(k, s.Service)
	return hmacSHA256(k, "aws4_request")
}

// canonical returns the canonical request and the signed header list.
func (s sigV4) canonical(req *http.Request, payloadHash string) (string, string) {
	path := req.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	if s.Service != "s3" {
		// Every service but S3 encodes the (already encoded) path again.
		segs := strings.Split(path, "/")
		for i, seg := range segs {
			if u, err := url.PathUnescape(seg); err == nil {
				seg = uriEncode(u, false)
			}
			segs[i] = uriEncode(seg, false)
		}
		path = strings.Join(segs, "/")
	}
	q := req.URL.Query()
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var qs []string
	for _, k := range keys {
		vals := append([]string(nil), q[k]...)
		sort.Strings(vals)
		for _, v := range vals {
			qs = append(qs, uriEncode(k, false)+"="+uriEncode(v, false))
		}
	}
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	headers := map[string]string{"host": host}
	for k, v := range req.Header {
		lk := strings.ToLower(k)
		if lk == "content-type" || strings.HasPrefix(lk, "x-amz-") {
			headers[lk] = strings.Join(strings.Fields(strings.Join(v, ",")), " ")
		}
	}
	names := make([]string, 0, len(headers))
	for k := range headers {
		names = append(names, k)
	}
	sort.Strings(names)
	var ch strings.Builder
	for _, k := range names {
		ch.WriteString(k + ":" + strings.TrimSpace(headers[k]) + "\n")
	}
	signed := strings.Join(names, ";")
	return strings.Join([]string{req.Method, path, strings.Join(qs, "&"), ch.String(), signed, payloadHash}, "\n"), signed
}

// sign adds X-Amz-Date and Authorization to req.
func (s sigV4) sign(req *http.Request, body []byte, now time.Time) {
	amzDate := now.UTC().Format("20060102T150405Z")
	date := amzDate[:8]
	req.Header.Set("X-Amz-Date", amzDate)
	creq, signed := s.canonical(req, sha256Hex(body))
	scope := date + "/" + s.Region + "/" + s.Service + "/aws4_request"
	sts := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + sha256Hex([]byte(creq))
	sig := hex.EncodeToString(hmacSHA256(s.signingKey(date), sts))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+s.AccessKey+"/"+scope+", SignedHeaders="+signed+", Signature="+sig)
}

// sesEndpoint is the SES API v2 SendEmail URL for a region.
func sesEndpoint(region string) string {
	return "https://email." + region + ".amazonaws.com/v2/email/outbound-emails"
}

func (d *Dispatcher) sendSES(ctx context.Context, ch *channelRow, m message) error {
	cfg := ch.Config
	if ch.secrets.SecretAccessKey == "" {
		return &sendError{Msg: "the secret access key is missing; enter it again"}
	}
	if !regionRE.MatchString(cfg.Region) {
		return &sendError{Msg: "invalid region"}
	}
	from := (&mail.Address{Name: "HardyOS (" + oneLine(m.Server) + ")", Address: cfg.From}).String()
	payload := map[string]any{
		"FromEmailAddress": from,
		"Destination":      map[string]any{"ToAddresses": cfg.To},
		"Content": map[string]any{"Simple": map[string]any{
			"Subject": map[string]string{"Data": m.subject(), "Charset": "UTF-8"},
			"Body": map[string]any{
				"Text": map[string]string{"Data": textBody(m), "Charset": "UTF-8"},
				"Html": map[string]string{"Data": htmlBody(m), "Charset": "UTF-8"},
			},
		}},
		"EmailTags": []map[string]string{{"Name": "source", "Value": "hardyos"}},
	}
	if cfg.ConfigurationSet != "" {
		payload["ConfigurationSetName"] = cfg.ConfigurationSet
	}
	body, _ := json.Marshal(payload)
	endpoint := sesEndpoint(cfg.Region)
	if d.sesEndpoint != nil {
		endpoint = d.sesEndpoint(cfg.Region)
	}
	signer := sigV4{AccessKey: cfg.AccessKeyID, SecretKey: ch.secrets.SecretAccessKey, Region: cfg.Region, Service: "ses"}
	return postJSON(ctx, d.client(), endpoint, body, func(r *http.Request) error {
		signer.sign(r, body, d.now())
		return nil
	})
}
