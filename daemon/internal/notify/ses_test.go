package notify

import (
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// AWS's published SigV4 examples: the IAM ListUsers request from the
// "Signature Version 4 signing process" documentation, and get-vanilla from
// the aws-sig-v4-test-suite.
func TestSigV4Vectors(t *testing.T) {
	when := time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
	const secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"

	iam := sigV4{AccessKey: "AKIDEXAMPLE", SecretKey: secret, Region: "us-east-1", Service: "iam"}
	if got := hex.EncodeToString(iam.signingKey("20150830")); got != "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9" {
		t.Errorf("signing key %s", got)
	}
	req, _ := http.NewRequest("GET", "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	req.Header.Set("X-Amz-Date", "20150830T123600Z")
	creq, signed := iam.canonical(req, sha256Hex(nil))
	if got := sha256Hex([]byte(creq)); got != "f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59" {
		t.Errorf("canonical request hash %s for\n%s", got, creq)
	}
	if signed != "content-type;host;x-amz-date" {
		t.Errorf("signed headers %q", signed)
	}
	iam.sign(req, nil, when)
	want := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
	if got := req.Header.Get("Authorization"); got != want {
		t.Errorf("authorization\n got %s\nwant %s", got, want)
	}

	vanilla := sigV4{AccessKey: "AKIDEXAMPLE", SecretKey: secret, Region: "us-east-1", Service: "service"}
	req, _ = http.NewRequest("GET", "https://example.amazonaws.com/", nil)
	vanilla.sign(req, nil, when)
	if got := req.Header.Get("Authorization"); !strings.HasSuffix(got, "SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31") {
		t.Errorf("get-vanilla authorization %s", got)
	}
}

func TestURIEncode(t *testing.T) {
	if got := uriEncode("a b/c~d*é", false); got != "a%20b%2Fc~d%2A%C3%A9" {
		t.Errorf("uriEncode %q", got)
	}
	if got := uriEncode("/a b/", true); got != "/a%20b/" {
		t.Errorf("uriEncode keep slash %q", got)
	}
}

func TestSESSend(t *testing.T) {
	var gotAuth, gotBody, gotPath, gotDate string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotPath, gotDate = r.Header.Get("Authorization"), r.URL.Path, r.Header.Get("X-Amz-Date")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"MessageId":"0100018"}`))
	}))
	defer srv.Close()
	d, _ := newTestDispatcher(t)
	d.httpc = srv.Client()
	d.sesEndpoint = func(string) string { return srv.URL + "/v2/email/outbound-emails" }
	d.Now = func() time.Time { return time.Date(2026, 10, 27, 9, 0, 0, 0, time.UTC) }
	ch := &channelRow{Channel: Channel{Type: TypeSES, Config: ChannelConfig{Region: "eu-west-1", AccessKeyID: "AKIAEXAMPLEEXAMPLE", From: "nas@example.com", To: []string{"cade@example.com"}}},
		secrets: Secrets{SecretAccessKey: "secretsecret"}}
	m := message{Event: Event{Kind: "pool.health", Severity: SeverityCritical, Title: "Pool tank is faulted", Body: "Open Storage Manager.", Time: d.now()}.normalize(), Server: "nas"}
	if err := d.sendSES(t.Context(), ch, m); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/v2/email/outbound-emails" || gotDate != "20261027T090000Z" {
		t.Errorf("path %q date %q", gotPath, gotDate)
	}
	if !strings.HasPrefix(gotAuth, "AWS4-HMAC-SHA256 Credential=AKIAEXAMPLEEXAMPLE/20261027/eu-west-1/ses/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=") {
		t.Errorf("authorization %q", gotAuth)
	}
	for _, want := range []string{`"ToAddresses":["cade@example.com"]`, `Critical: Pool tank is faulted`, `"FromEmailAddress":"\"HardyOS (nas)\" \u003cnas@example.com\u003e"`} {
		if !strings.Contains(gotBody, want) {
			t.Errorf("body lacks %s:\n%s", want, gotBody)
		}
	}
	if strings.Contains(gotBody, "secretsecret") {
		t.Error("secret key in the request body")
	}
}
