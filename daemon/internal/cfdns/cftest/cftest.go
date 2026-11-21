// Package cftest is a fake Cloudflare DNS API for tests: tokens, one or more
// zones and their records in memory, served by httptest.
package cftest

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"

	"github.com/hardyos/hardyos/daemon/internal/cfdns"
)

// Server is a fake Cloudflare.
type Server struct {
	*httptest.Server

	mu sync.Mutex
	// Tokens maps a token to its status ("active", "disabled").
	Tokens map[string]string
	// Zones maps a zone name to its id.
	Zones map[string]string
	// ZoneStatus overrides a zone's status (default "active").
	ZoneStatus map[string]string
	// Account owns every zone; AccountTokens are account-owned tokens
	// (only /accounts/{Account}/tokens/verify knows them).
	Account       string
	AccountTokens map[string]bool
	records       map[string]*rec // by id
	// Calls counts requests by "METHOD path".
	Calls map[string]int
	// Seen are the Authorization headers received.
	Seen []string
}

type rec struct {
	zone string
	cfdns.Record
}

func id() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// New starts a fake with one active token and one zone.
func New(token, zone string) *Server {
	s := &Server{Tokens: map[string]string{token: "active"}, Zones: map[string]string{zone: id()},
		records: map[string]*rec{}, Calls: map[string]int{}, ZoneStatus: map[string]string{}, Account: id(), AccountTokens: map[string]bool{}}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	return s
}

// Client is a cfdns client for this fake.
func (s *Server) Client(token string) *cfdns.Client {
	return cfdns.NewForTest(token, s.URL, s.Server.Client())
}

// Add puts a record in a zone (someone else's record, unless comment says
// otherwise) and returns its id.
func (s *Server) Add(zone string, r cfdns.Record) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	r.ID = id()
	s.records[r.ID] = &rec{zone: s.Zones[zone], Record: r}
	return r.ID
}

// Find returns the records with a name (and type, unless "").
func (s *Server) Find(name, typ string) []cfdns.Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []cfdns.Record
	for _, r := range s.records {
		if r.Name == name && (typ == "" || r.Type == typ) {
			out = append(out, r.Record)
		}
	}
	return out
}

// TXT returns the values of TXT records with a name.
func (s *Server) TXT(name string) []string {
	var out []string
	for _, r := range s.Find(name, "TXT") {
		out = append(out, r.Content)
	}
	return out
}

// Count is how many records there are.
func (s *Server) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.records)
}

func (s *Server) reply(w http.ResponseWriter, status int, result any, errMsg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if errMsg != "" {
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "errors": []map[string]any{{"code": 1000, "message": errMsg}}})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "errors": []any{}, "result": result})
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Calls[r.Method+" "+r.URL.Path]++
	s.Seen = append(s.Seen, r.Header.Get("Authorization"))
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	st, ok := s.Tokens[tok]
	if !ok {
		s.reply(w, http.StatusForbidden, nil, "Invalid API Token")
		return
	}
	p := r.URL.Path
	switch {
	case p == "/user/tokens/verify" && r.Method == http.MethodGet:
		if s.AccountTokens[tok] {
			s.reply(w, 401, nil, "Invalid API Token")
			return
		}
		s.reply(w, 200, map[string]string{"id": "t", "status": st}, "")
	case p == "/accounts/"+s.Account+"/tokens/verify" && r.Method == http.MethodGet:
		if !s.AccountTokens[tok] {
			s.reply(w, 401, nil, "Invalid API Token")
			return
		}
		s.reply(w, 200, map[string]string{"id": "t", "status": st}, "")
	case st != "active":
		s.reply(w, http.StatusForbidden, nil, "token disabled")
	case p == "/zones" && r.Method == http.MethodGet:
		name := r.URL.Query().Get("name")
		out := []map[string]any{}
		if zid, ok := s.Zones[name]; ok {
			zs := "active"
			if v := s.ZoneStatus[name]; v != "" {
				zs = v
			}
			out = append(out, map[string]any{"id": zid, "name": name, "status": zs, "account": map[string]string{"id": s.Account}})
		}
		s.reply(w, 200, out, "")
	case strings.HasPrefix(p, "/zones/"):
		parts := strings.Split(strings.TrimPrefix(p, "/zones/"), "/")
		zid := parts[0]
		known := false
		for _, v := range s.Zones {
			known = known || v == zid
		}
		if !known || len(parts) < 2 || parts[1] != "dns_records" {
			s.reply(w, 404, nil, "not found")
			return
		}
		if len(parts) == 2 {
			switch r.Method {
			case http.MethodGet:
				q := r.URL.Query()
				out := []cfdns.Record{}
				for _, x := range s.records {
					if x.zone == zid && (q.Get("name") == "" || x.Name == q.Get("name")) && (q.Get("type") == "" || x.Type == q.Get("type")) {
						out = append(out, x.Record)
					}
				}
				s.reply(w, 200, out, "")
			case http.MethodPost:
				var in cfdns.Record
				if json.NewDecoder(r.Body).Decode(&in) != nil || in.Name == "" || in.Type == "" {
					s.reply(w, 400, nil, "bad record")
					return
				}
				in.ID = id()
				s.records[in.ID] = &rec{zone: zid, Record: in}
				s.reply(w, 200, in, "")
			default:
				s.reply(w, 405, nil, "method")
			}
			return
		}
		x := s.records[parts[2]]
		if x == nil || x.zone != zid {
			s.reply(w, 404, nil, "Record does not exist")
			return
		}
		switch r.Method {
		case http.MethodPut:
			var in cfdns.Record
			if json.NewDecoder(r.Body).Decode(&in) != nil {
				s.reply(w, 400, nil, "bad record")
				return
			}
			in.ID = x.ID
			x.Record = in
			s.reply(w, 200, in, "")
		case http.MethodDelete:
			delete(s.records, x.ID)
			s.reply(w, 200, map[string]string{"id": x.ID}, "")
		default:
			s.reply(w, 405, nil, "method")
		}
	default:
		s.reply(w, 404, nil, "not found")
	}
}
