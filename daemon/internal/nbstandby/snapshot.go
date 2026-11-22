// Package nbstandby is the NetBird standby server (docs/netbird-standby.md,
// decisions 420-429): hardyd-priv pulls snapshots of the VPS's NetBird
// server over a restricted SSH key, keeps them sealed, and on a take-over
// stages the newest one into the netbird-standby app; hardyd schedules the
// syncs, raises alerts and runs take-over and hand-back as jobs.
package nbstandby

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"io"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
)

// A snapshot is a tar made by the VPS's forced command (VerbSnapshot). Only
// these entries may be in it, regular files only, each at most its size.
const (
	EntryManifest  = "manifest.json"
	EntryConfig    = "config/config.yaml"
	EntryDashboard = "config/dashboard.env"
	EntryServerEnv = "config/server.env"
	EntryStore     = "data/store.db"
	EntryIDP       = "data/idp.db"
	EntryEvents    = "data/events.db"
	EntryACME      = "tls/acme.json"
)

// MaxSnapshot bounds a whole snapshot (the tar stream).
const MaxSnapshot int64 = 1 << 30

var entryLimits = map[string]int64{
	EntryManifest:  64 << 10,
	EntryConfig:    1 << 20,
	EntryDashboard: 64 << 10,
	EntryServerEnv: 16 << 10,
	EntryStore:     900 << 20,
	EntryIDP:       256 << 20,
	EntryEvents:    900 << 20,
	EntryACME:      4 << 20,
}

var entryDirs = map[string]bool{"config": true, "data": true, "tls": true}

// SecretEnv are the NetBird server's environment variables the snapshot
// may carry (config/server.env): set in the VPS's container instead of
// config.yaml, they are folded into config.yaml when staging.
var SecretEnv = map[string]string{
	"NB_STORE_ENCRYPTION_KEY":              "encryptionKey",
	"NB_AUTH_SECRET":                       "authSecret",
	"NB_IDP_SESSION_COOKIE_ENCRYPTION_KEY": "sessionCookieEncryptionKey",
}

var sqliteMagic = []byte("SQLite format 3\x00")

// Manifest is the snapshot's own description, written by the VPS script.
type Manifest struct {
	Format    int               `json:"format"`
	Created   time.Time         `json:"created"`
	Hostname  string            `json:"hostname"`
	Image     string            `json:"image"`
	Digest    string            `json:"digest"`
	Version   string            `json:"version"`
	Engine    string            `json:"engine"`
	Peers     int               `json:"peers"`
	SetupKeys int               `json:"setupKeys"`
	Files     map[string]string `json:"files"` // entry -> SHA-256 (hex)
}

// Info is what a checked snapshot tells (no secrets).
type Info struct {
	Created  time.Time `json:"created"`
	Hostname string    `json:"hostname"`
	Image    string    `json:"image"`
	Digest   string    `json:"digest"`
	Version  string    `json:"version"`
	// Peers and SetupKeys are the VPS's own counts (informational).
	Peers     int      `json:"peers"`
	SetupKeys int      `json:"setupKeys"`
	Files     []string `json:"files"`
	// Bytes is the tar's size; SHA256 its hash.
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
	// CertNotAfter is when the hostname's certificate in acme.json ends
	// (zero without one).
	CertNotAfter time.Time `json:"certNotAfter,omitzero"`
	Warnings     []string  `json:"warnings"`
}

// File is one checked entry kept in memory (configs) or streamed (databases).
type checked struct {
	info   Info
	config []byte
	env    map[string]string
	acme   []byte
	// sink receives each entry's bytes while it is checked (stage writes
	// them out; sync discards them).
	files map[string]string // entry -> sha256 seen
}

// Sink receives a checked entry's contents while it is read. Begin returns
// the writer for an entry (nil to discard).
type Sink interface {
	Begin(name string, mode int64) (io.Writer, error)
	End(name string) error
}

var hostRE = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

// ValidHostname reports whether h is a lower-case DNS name with at least
// two labels.
func ValidHostname(h string) bool { return len(h) <= 253 && hostRE.MatchString(h) }

// Check reads a snapshot tar from r and checks every entry: names from the
// list only (once each), regular files, sizes, the SQLite header of each
// database, the hashes in the manifest (which must come first and list
// exactly the other entries), the hostname (wantHost) in the manifest and in
// config.yaml, and a SQLite store. Entries go to sink as they are read (nil
// discards them): the caller only trusts what it wrote once Check returned
// no error.
func Check(r io.Reader, wantHost string, sink Sink) (*Info, error) {
	c, err := check(r, wantHost, sink)
	if err != nil {
		return nil, err
	}
	return &c.info, nil
}

func check(r io.Reader, wantHost string, sink Sink) (*checked, error) {
	if !ValidHostname(wantHost) {
		return nil, errors.New("no NetBird hostname is configured")
	}
	counted := &countingHash{r: io.LimitReader(r, MaxSnapshot+1), h: sha256.New()}
	tr := tar.NewReader(counted)
	c := &checked{files: map[string]string{}, env: map[string]string{}}
	var man *Manifest
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			if counted.n > MaxSnapshot {
				return nil, fmt.Errorf("the snapshot is larger than %d MiB", MaxSnapshot>>20)
			}
			return nil, fmt.Errorf("the snapshot isn't a valid tar: %v", clipErr(err))
		}
		name := strings.TrimPrefix(path.Clean(strings.TrimPrefix(hdr.Name, "./")), "./")
		if hdr.Typeflag == tar.TypeDir {
			if !entryDirs[strings.TrimSuffix(name, "/")] {
				return nil, fmt.Errorf("unexpected folder %q in the snapshot", clip(hdr.Name, 80))
			}
			continue
		}
		limit, ok := entryLimits[name]
		if !ok || name != strings.TrimPrefix(hdr.Name, "./") {
			return nil, fmt.Errorf("unexpected entry %q in the snapshot", clip(hdr.Name, 80))
		}
		if hdr.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("%s isn't a regular file in the snapshot", name)
		}
		if _, dup := c.files[name]; dup || (name == EntryManifest && man != nil) {
			return nil, fmt.Errorf("%s is in the snapshot twice", name)
		}
		if hdr.Size < 0 || hdr.Size > limit {
			return nil, fmt.Errorf("%s is larger than %d KiB", name, limit>>10)
		}
		if man == nil && name != EntryManifest {
			return nil, errors.New("the snapshot must start with manifest.json")
		}
		if name == EntryManifest {
			b, err := io.ReadAll(io.LimitReader(tr, limit))
			if err != nil {
				return nil, err
			}
			man = &Manifest{}
			dec := json.NewDecoder(bytes.NewReader(b))
			if err := dec.Decode(man); err != nil {
				return nil, fmt.Errorf("manifest.json: %v", clipErr(err))
			}
			continue
		}
		if err := c.entry(tr, hdr, name, sink); err != nil {
			return nil, err
		}
	}
	if counted.n > MaxSnapshot {
		return nil, fmt.Errorf("the snapshot is larger than %d MiB", MaxSnapshot>>20)
	}
	// Whatever follows the tar's end (padding) still counts and is hashed.
	if _, err := io.Copy(io.Discard, counted); err != nil {
		return nil, err
	}
	if counted.n > MaxSnapshot {
		return nil, fmt.Errorf("the snapshot is larger than %d MiB", MaxSnapshot>>20)
	}
	if man == nil {
		return nil, errors.New("the snapshot has no manifest.json")
	}
	if err := c.finish(man, wantHost); err != nil {
		return nil, err
	}
	c.info.Bytes = counted.n
	c.info.SHA256 = hex.EncodeToString(counted.h.Sum(nil))
	return c, nil
}

func (c *checked) entry(tr io.Reader, hdr *tar.Header, name string, sink Sink) error {
	h := sha256.New()
	var w io.Writer = h
	if sink != nil {
		sw, err := sink.Begin(name, hdr.Mode)
		if err != nil {
			return err
		}
		if sw != nil {
			w = io.MultiWriter(h, sw)
		}
	}
	var keep *bytes.Buffer
	switch name {
	case EntryConfig, EntryServerEnv, EntryACME, EntryDashboard:
		keep = &bytes.Buffer{}
		w = io.MultiWriter(w, keep)
	}
	var head []byte
	if strings.HasPrefix(name, "data/") {
		head = make([]byte, len(sqliteMagic))
		n, _ := io.ReadFull(tr, head)
		head = head[:n]
		if !bytes.Equal(head, sqliteMagic) {
			return fmt.Errorf("%s isn't a SQLite database", name)
		}
		if _, err := w.Write(head); err != nil {
			return err
		}
	}
	n, err := io.Copy(w, tr)
	if err != nil {
		return fmt.Errorf("reading %s: %v", name, clipErr(err))
	}
	if n+int64(len(head)) != hdr.Size {
		return fmt.Errorf("%s is cut short", name)
	}
	if sink != nil {
		if err := sink.End(name); err != nil {
			return err
		}
	}
	c.files[name] = hex.EncodeToString(h.Sum(nil))
	switch name {
	case EntryConfig:
		c.config = keep.Bytes()
	case EntryACME:
		c.acme = keep.Bytes()
	case EntryServerEnv:
		env, err := parseServerEnv(keep.Bytes())
		if err != nil {
			return err
		}
		c.env = env
	}
	return nil
}

func (c *checked) finish(man *Manifest, wantHost string) error {
	if man.Format != 1 {
		return fmt.Errorf("snapshot format %d isn't one this HardyOS reads", man.Format)
	}
	if strings.ToLower(man.Hostname) != wantHost {
		return fmt.Errorf("the snapshot is of %q, not %s", clip(man.Hostname, 80), wantHost)
	}
	if man.Engine != "sqlite" {
		return fmt.Errorf("the VPS's NetBird store is %q: only SQLite is supported", clip(man.Engine, 20))
	}
	for _, req := range []string{EntryConfig, EntryStore} {
		if _, ok := c.files[req]; !ok {
			return fmt.Errorf("the snapshot has no %s", req)
		}
	}
	if len(man.Files) != len(c.files) {
		return errors.New("the snapshot's manifest doesn't list exactly its files")
	}
	for name, sum := range c.files {
		if want, ok := man.Files[name]; !ok || !strings.EqualFold(want, sum) {
			return fmt.Errorf("%s doesn't match the manifest's checksum", name)
		}
	}
	host, warnings, err := CheckConfig(c.config)
	if err != nil {
		return err
	}
	if host != wantHost {
		return fmt.Errorf("config.yaml is for %q, not %s", clip(host, 80), wantHost)
	}
	c.info = Info{Created: man.Created.UTC(), Hostname: wantHost, Image: clip(man.Image, 200), Digest: clip(man.Digest, 100),
		Version: clip(man.Version, 40), Peers: max(man.Peers, 0), SetupKeys: max(man.SetupKeys, 0), Warnings: warnings}
	for name := range c.files {
		c.info.Files = append(c.info.Files, name)
	}
	sort.Strings(c.info.Files)
	if len(c.acme) > 0 {
		if na, ok := acmeNotAfter(c.acme, wantHost); ok {
			c.info.CertNotAfter = na
		} else {
			c.info.Warnings = append(c.info.Warnings, "acme.json has no certificate for "+wantHost+": Traefik gets one after a take-over (TCP 443 must reach this server)")
		}
	} else {
		c.info.Warnings = append(c.info.Warnings, "no Traefik certificate store (tls/acme.json) on the VPS: Traefik gets a certificate after a take-over")
	}
	for k := range c.env {
		if !configHasKey(c.config, SecretEnv[k]) {
			return fmt.Errorf("the VPS sets %s in the environment but config.yaml has no %s line to carry it", k, SecretEnv[k])
		}
	}
	return nil
}

type countingHash struct {
	r io.Reader
	h hash.Hash
	n int64
}

func (c *countingHash) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	c.h.Write(p[:n])
	return n, err
}

var envLineRE = regexp.MustCompile(`^([A-Z_]+)=([A-Za-z0-9+/=_.-]{1,512})$`)

func parseServerEnv(b []byte) (map[string]string, error) {
	out := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m := envLineRE.FindStringSubmatch(line)
		if m == nil || SecretEnv[m[1]] == "" {
			return nil, errors.New("config/server.env holds something other than NetBird's three secret variables")
		}
		out[m[1]] = m[2]
	}
	return out, nil
}

// ---- config.yaml --------------------------------------------------------------

// yamlKeyRE is one "key: value" line (value optional, quoted or plain).
var yamlKeyRE = regexp.MustCompile(`^(\s*)([A-Za-z][A-Za-z0-9]*):\s*(.*?)\s*$`)

type yamlLine struct {
	indent int
	key    string
	value  string
	path   string // dotted path of keys, e.g. server.store.engine
}

// yamlKeys reads the plain "key: value" lines of a YAML block mapping with
// their dotted paths (lists, flow values and comments are skipped). It is
// not a YAML parser: it only finds the few keys HardyOS checks, and
// anything it doesn't understand is left as it is.
func yamlKeys(b []byte) []yamlLine {
	var out []yamlLine
	type frame struct {
		indent int
		key    string
	}
	var stack []frame
	for _, raw := range strings.Split(string(b), "\n") {
		line := strings.TrimRight(raw, "\r")
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") || strings.HasPrefix(trim, "-") {
			continue
		}
		m := yamlKeyRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		indent := len(m[1])
		for len(stack) > 0 && stack[len(stack)-1].indent >= indent {
			stack = stack[:len(stack)-1]
		}
		var keys []string
		for _, f := range stack {
			keys = append(keys, f.key)
		}
		keys = append(keys, m[2])
		val := m[3]
		if i := strings.Index(val, " #"); i >= 0 && !strings.HasPrefix(val, `"`) && !strings.HasPrefix(val, "'") {
			val = strings.TrimSpace(val[:i])
		}
		out = append(out, yamlLine{indent: indent, key: m[2], value: unquote(val), path: strings.Join(keys, ".")})
		if val == "" {
			stack = append(stack, frame{indent: indent, key: m[2]})
		}
	}
	return out
}

func unquote(v string) string {
	if i := strings.Index(v, `" #`); strings.HasPrefix(v, `"`) && i > 0 {
		v = v[:i+1]
	}
	if len(v) >= 2 && (v[0] == '"' && v[len(v)-1] == '"' || v[0] == '\'' && v[len(v)-1] == '\'') {
		return v[1 : len(v)-1]
	}
	return v
}

func configValue(b []byte, p string) (string, bool) {
	for _, l := range yamlKeys(b) {
		if l.path == p {
			return l.value, true
		}
	}
	return "", false
}

func configHasKey(b []byte, key string) bool {
	for _, l := range yamlKeys(b) {
		if l.key == key {
			return true
		}
	}
	return false
}

// CheckConfig checks the VPS's config.yaml is a combined server config this
// standby can run: SQLite store in the default file, data in
// /var/lib/netbird, and returns the hostname of its exposedAddress.
func CheckConfig(b []byte) (host string, warnings []string, err error) {
	if len(b) == 0 {
		return "", nil, errors.New("config.yaml is empty")
	}
	addr, ok := configValue(b, "server.exposedAddress")
	if !ok {
		return "", nil, errors.New("config.yaml has no server.exposedAddress: only NetBird's combined server (config.yaml) is supported")
	}
	rest, ok := strings.CutPrefix(addr, "https://")
	if !ok {
		return "", nil, fmt.Errorf("exposedAddress %q isn't https", clip(addr, 80))
	}
	host = strings.ToLower(rest)
	if i := strings.IndexAny(host, ":/"); i >= 0 {
		port := host[i:]
		host = host[:i]
		if port != ":443" && port != ":443/" && port != "/" {
			warnings = append(warnings, "the NetBird server isn't on port 443; the router must forward that port to 44621 instead")
		}
	}
	if !ValidHostname(host) {
		return "", nil, fmt.Errorf("exposedAddress %q has no valid hostname", clip(addr, 80))
	}
	if e, _ := configValue(b, "server.store.engine"); e != "" && e != "sqlite" {
		return "", nil, fmt.Errorf("the store engine is %q: only SQLite is supported", clip(e, 20))
	}
	if d, _ := configValue(b, "server.store.dsn"); d != "" {
		return "", nil, errors.New("the store has a database address (dsn): only SQLite is supported")
	}
	if f, _ := configValue(b, "server.store.file"); f != "" && f != "/var/lib/netbird/store.db" {
		return "", nil, errors.New("the store is in a custom file: only the default /var/lib/netbird/store.db is supported")
	}
	if d, ok := configValue(b, "server.dataDir"); ok && strings.TrimSuffix(d, "/") != "/var/lib/netbird" {
		return "", nil, errors.New("dataDir isn't /var/lib/netbird: only NetBird's default layout is supported")
	}
	for _, p := range []string{"server.activityStore.engine", "server.authStore.engine", "server.accessLogStore.engine"} {
		if e, _ := configValue(b, p); e == "postgres" {
			return "", nil, fmt.Errorf("%s is postgres: only SQLite is supported", p)
		}
	}
	if v, _ := configValue(b, "server.tls.letsencrypt.enabled"); v == "true" {
		warnings = append(warnings, "the server gets its own Let's Encrypt certificate (tls.letsencrypt); the standby serves TLS with Traefik")
	}
	return host, warnings, nil
}

var secretValueRE = regexp.MustCompile(`^[A-Za-z0-9+/=_.-]{1,512}$`)

// FoldSecrets writes the values of env (SecretEnv names) over the matching
// keys' lines in config.yaml, keeping their indentation. Every key must have
// a line (CheckConfig's caller verified it); values are restricted to
// base64-like characters, so nothing can break out of the quotes.
func FoldSecrets(cfg []byte, env map[string]string) ([]byte, error) {
	if len(env) == 0 {
		return cfg, nil
	}
	lines := strings.Split(string(cfg), "\n")
	for name, val := range env {
		key := SecretEnv[name]
		if key == "" || !secretValueRE.MatchString(val) {
			return nil, fmt.Errorf("bad value for %s", name)
		}
		done := false
		for i, l := range lines {
			m := yamlKeyRE.FindStringSubmatch(strings.TrimRight(l, "\r"))
			if m != nil && m[2] == key {
				lines[i] = m[1] + key + `: "` + val + `"`
				done = true
			}
		}
		if !done {
			return nil, fmt.Errorf("config.yaml has no %s line", key)
		}
	}
	return []byte(strings.Join(lines, "\n")), nil
}

// ---- acme.json ------------------------------------------------------------------

// acmeNotAfter finds host's certificate (main domain or a SAN) in a Traefik
// acme.json and returns when it ends.
func acmeNotAfter(b []byte, host string) (time.Time, bool) {
	var store map[string]struct {
		Certificates []struct {
			Domain struct {
				Main string   `json:"main"`
				SANs []string `json:"sans"`
			} `json:"domain"`
			Certificate string `json:"certificate"`
		} `json:"Certificates"`
	}
	if err := json.Unmarshal(b, &store); err != nil {
		return time.Time{}, false
	}
	var best time.Time
	for _, res := range store {
		for _, c := range res.Certificates {
			names := append([]string{c.Domain.Main}, c.Domain.SANs...)
			match := false
			for _, n := range names {
				match = match || strings.EqualFold(n, host)
			}
			if !match {
				continue
			}
			der, err := base64.StdEncoding.DecodeString(c.Certificate)
			if err != nil {
				continue
			}
			blk, _ := pem.Decode(der)
			if blk == nil {
				continue
			}
			cert, err := x509.ParseCertificate(blk.Bytes)
			if err != nil || cert.VerifyHostname(host) != nil {
				continue
			}
			if cert.NotAfter.After(best) {
				best = cert.NotAfter.UTC()
			}
		}
	}
	return best, !best.IsZero()
}

// ---- helpers --------------------------------------------------------------------

func clip(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if len([]rune(s)) <= n {
		return s
	}
	return string([]rune(s)[:n]) + "…"
}

func clipErr(err error) string { return clip(err.Error(), 200) }
