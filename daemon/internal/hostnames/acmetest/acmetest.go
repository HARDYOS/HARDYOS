// Package acmetest is a fake ACME server (the RFC 8555 subset
// golang.org/x/crypto/acme uses for one order with DNS-01) for tests. It
// validates a challenge only when Lookup shows the right TXT record, and
// signs certificates with its own throw-away CA.
package acmetest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
)

// Server is a fake ACME CA.
type Server struct {
	*httptest.Server
	// Lookup returns the TXT values published for a name (the fake
	// Cloudflare's records).
	Lookup func(name string) []string
	// Validity of issued certificates (default 90 days).
	Validity time.Duration
	// Now is the CA's clock (default time.Now).
	Now func() time.Time

	mu      sync.Mutex
	caKey   *ecdsa.PrivateKey
	ca      *x509.Certificate
	caDER   []byte
	thumb   string
	orders  map[string]*order
	nextID  int
	Issued  int
	Checked []string // challenge names looked up
}

type order struct {
	ids    []acme.AuthzID
	authzs []*authz
	status string
	cert   []byte // PEM chain
}

type authz struct {
	id       string
	ident    acme.AuthzID
	wildcard bool
	token    string
	status   string
}

// New starts the fake.
func New() *Server {
	s := &Server{orders: map[string]*order{}, Validity: 90 * 24 * time.Hour}
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Fake ACME CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	s.caKey, s.caDER = k, der
	s.ca, _ = x509.ParseCertificate(der)
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	return s
}

// Directory is the directory URL.
func (s *Server) Directory() string { return s.URL + "/directory" }

// CA is the fake CA's certificate (for verifying chains).
func (s *Server) CA() *x509.Certificate { return s.ca }

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

type jws struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type header struct {
	JWK *struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
		Y   string `json:"y"`
	} `json:"jwk"`
	KID string `json:"kid"`
	URL string `json:"url"`
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (s *Server) problem(w http.ResponseWriter, status int, typ, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"type": "urn:ietf:params:acme:error:" + typ, "detail": detail, "status": status})
}

func (s *Server) json(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) id() string {
	s.nextID++
	return fmt.Sprint(s.nextID)
}

func (s *Server) authzJSON(a *authz) map[string]any {
	ch := map[string]any{"type": "dns-01", "url": s.URL + "/chal/" + a.id, "token": a.token, "status": map[string]string{"valid": "valid", "invalid": "invalid"}[a.status]}
	if ch["status"] == "" {
		ch["status"] = "pending"
	}
	return map[string]any{"status": a.status, "identifier": a.ident, "wildcard": a.wildcard, "challenges": []any{ch},
		"expires": s.now().Add(24 * time.Hour).Format(time.RFC3339)}
}

func (s *Server) orderJSON(id string, o *order) map[string]any {
	var urls []string
	for _, a := range o.authzs {
		urls = append(urls, s.URL+"/authz/"+a.id)
	}
	out := map[string]any{"status": o.status, "identifiers": o.ids, "authorizations": urls, "finalize": s.URL + "/finalize/" + id,
		"expires": s.now().Add(24 * time.Hour).Format(time.RFC3339)}
	if o.cert != nil {
		out["certificate"] = s.URL + "/cert/" + id
	}
	return out
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w.Header().Set("Replay-Nonce", b64([]byte(fmt.Sprint(time.Now().UnixNano()))))
	w.Header().Set("Cache-Control", "no-store")
	p := r.URL.Path
	if p == "/directory" {
		s.json(w, 200, map[string]any{"newNonce": s.URL + "/new-nonce", "newAccount": s.URL + "/new-account",
			"newOrder": s.URL + "/new-order", "revokeCert": s.URL + "/revoke", "keyChange": s.URL + "/key-change"})
		return
	}
	if p == "/new-nonce" {
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.Method != http.MethodPost {
		s.problem(w, 405, "malformed", "POST only")
		return
	}
	var body jws
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		s.problem(w, 400, "malformed", "not JWS")
		return
	}
	hb, _ := base64.RawURLEncoding.DecodeString(body.Protected)
	var h header
	_ = json.Unmarshal(hb, &h)
	payload, _ := base64.RawURLEncoding.DecodeString(body.Payload)
	switch {
	case p == "/new-account":
		if h.JWK == nil {
			s.problem(w, 400, "malformed", "no jwk")
			return
		}
		x, _ := base64.RawURLEncoding.DecodeString(h.JWK.X)
		y, _ := base64.RawURLEncoding.DecodeString(h.JWK.Y)
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		t, err := acme.JWKThumbprint(pub)
		if err != nil {
			s.problem(w, 400, "malformed", err.Error())
			return
		}
		status := 201
		if s.thumb == t {
			status = 200
		}
		s.thumb = t
		w.Header().Set("Location", s.URL+"/acct/1")
		s.json(w, status, map[string]any{"status": "valid", "orders": s.URL + "/orders"})
	case strings.HasPrefix(p, "/acct/"):
		s.json(w, 200, map[string]any{"status": "valid"})
	case p == "/new-order":
		var in struct {
			Identifiers []acme.AuthzID `json:"identifiers"`
		}
		_ = json.Unmarshal(payload, &in)
		oid := s.id()
		o := &order{ids: in.Identifiers, status: "pending"}
		for _, id := range in.Identifiers {
			a := &authz{id: s.id(), status: "pending", token: b64([]byte("token-" + oid + "-" + id.Value))}
			a.ident = acme.AuthzID{Type: "dns", Value: strings.TrimPrefix(id.Value, "*.")}
			a.wildcard = strings.HasPrefix(id.Value, "*.")
			o.authzs = append(o.authzs, a)
		}
		s.orders[oid] = o
		w.Header().Set("Location", s.URL+"/order/"+oid)
		s.json(w, 201, s.orderJSON(oid, o))
	case strings.HasPrefix(p, "/authz/"):
		a := s.findAuthz(strings.TrimPrefix(p, "/authz/"))
		if a == nil {
			s.problem(w, 404, "malformed", "no authz")
			return
		}
		s.json(w, 200, s.authzJSON(a))
	case strings.HasPrefix(p, "/chal/"):
		a := s.findAuthz(strings.TrimPrefix(p, "/chal/"))
		if a == nil {
			s.problem(w, 404, "malformed", "no challenge")
			return
		}
		if a.status == "pending" {
			sum := sha256.Sum256([]byte(a.token + "." + s.thumb))
			want := b64(sum[:])
			name := "_acme-challenge." + a.ident.Value
			s.Checked = append(s.Checked, name)
			a.status = "invalid"
			if s.Lookup != nil {
				for _, v := range s.Lookup(name) {
					if v == want {
						a.status = "valid"
					}
				}
			}
		}
		ch := s.authzJSON(a)["challenges"].([]any)[0]
		s.json(w, 200, ch)
	case strings.HasPrefix(p, "/order/"):
		oid := strings.TrimPrefix(p, "/order/")
		o := s.orders[oid]
		if o == nil {
			s.problem(w, 404, "malformed", "no order")
			return
		}
		s.refresh(o)
		s.json(w, 200, s.orderJSON(oid, o))
	case strings.HasPrefix(p, "/finalize/"):
		oid := strings.TrimPrefix(p, "/finalize/")
		o := s.orders[oid]
		if o == nil {
			s.problem(w, 404, "malformed", "no order")
			return
		}
		s.refresh(o)
		if o.status != "ready" {
			s.problem(w, 403, "orderNotReady", "order is "+o.status)
			return
		}
		var in struct {
			CSR string `json:"csr"`
		}
		_ = json.Unmarshal(payload, &in)
		der, _ := base64.RawURLEncoding.DecodeString(in.CSR)
		csr, err := x509.ParseCertificateRequest(der)
		if err != nil || csr.CheckSignature() != nil {
			s.problem(w, 400, "badCSR", "bad CSR")
			return
		}
		for _, n := range csr.DNSNames {
			ok := false
			for _, id := range o.ids {
				ok = ok || id.Value == n
			}
			if !ok {
				s.problem(w, 400, "badCSR", "CSR names "+n)
				return
			}
		}
		now := s.now()
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(int64(1000 + s.Issued)), Subject: pkix.Name{CommonName: csr.DNSNames[0]},
			DNSNames: csr.DNSNames, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(s.Validity),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		leaf, err := x509.CreateCertificate(rand.Reader, tmpl, s.ca, csr.PublicKey, s.caKey)
		if err != nil {
			s.problem(w, 500, "serverInternal", err.Error())
			return
		}
		s.Issued++
		o.cert = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.caDER})...)
		o.status = "valid"
		w.Header().Set("Location", s.URL+"/order/"+oid)
		s.json(w, 200, s.orderJSON(oid, o))
	case strings.HasPrefix(p, "/cert/"):
		o := s.orders[strings.TrimPrefix(p, "/cert/")]
		if o == nil || o.cert == nil {
			s.problem(w, 404, "malformed", "no certificate")
			return
		}
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		w.WriteHeader(200)
		_, _ = w.Write(o.cert)
	default:
		s.problem(w, 404, "malformed", "unknown path")
	}
}

func (s *Server) findAuthz(id string) *authz {
	for _, o := range s.orders {
		for _, a := range o.authzs {
			if a.id == id {
				return a
			}
		}
	}
	return nil
}

func (s *Server) refresh(o *order) {
	if o.status != "pending" {
		return
	}
	all := true
	for _, a := range o.authzs {
		if a.status == "invalid" {
			o.status = "invalid"
			return
		}
		all = all && a.status == "valid"
	}
	if all {
		o.status = "ready"
	}
}
