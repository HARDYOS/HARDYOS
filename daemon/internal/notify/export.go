package notify

import (
	"net/http"
	"time"
)

// SignAWS signs req (with its body) with AWS Signature Version 4 for a
// service in a region. The mail server's SES identity checks use it.
func SignAWS(req *http.Request, body []byte, accessKey, secretKey, region, service string, now time.Time) {
	sigV4{AccessKey: accessKey, SecretKey: secretKey, Region: region, Service: service}.sign(req, body, now)
}

// GuardedClient is an HTTP client that refuses local and private
// addresses at dial time and never follows redirects (allowLocal turns
// the address check off, for tests).
func GuardedClient(allowLocal bool) *http.Client { return guardedClient(allowLocal) }
