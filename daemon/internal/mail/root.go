package mail

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"math/big"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/hardyos/hardyos/daemon/internal/rootfile"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// PropMail marks the mail dataset as HardyOS's own.
const PropMail = "org.hardyos:mail"

// RunTLSDir is root's copy of the certificate and key the mail programs
// read (made on every apply and start from the pool's copy).
const RunTLSDir = "/run/hardyos-mail/tls"

// Services by role; ClamAV's only while it's on.
var (
	coreUnits   = []string{RedisUnit, "rspamd.service", "dovecot.service", "postfix.service", "radicale.service"}
	clamavUnits = []string{"clamav-freshclam.service", "clamav-daemon.service"}
)

// Root runs the mail server. It lives in hardyd-priv.
type Root struct {
	Runner sysexec.Runner
	Log    *slog.Logger
	// StateFile keeps the last applied setup (with its secrets) so the
	// server comes back after a restart or an update (default
	// rootfile.RootStateDir/mail.json).
	StateFile string
	// Hooks for tests: file writes, ownership, user lookups and the mail
	// dataset's mountpoint. The defaults are the real ones.
	Write      func(path string, data []byte, mode os.FileMode) error
	Chown      func(path string, uid, gid int) error
	LookupUser func(name string) (uid, gid int, err error)
	LookupGrp  func(name string) (gid int, err error)
	Dataset    func(ctx context.Context, pool string) (mountpoint string, err error)
	// SkipChecks skips the configuration checks that need the programs
	// installed (tests).
	SkipChecks bool
	// DovecotLog sends Dovecot's log to a file with sign-in debugging
	// (tests).
	DovecotLog string
	// StartServices replaces the firewall and systemd steps (tests in a
	// container without systemd start the daemons themselves).
	StartServices func(ctx context.Context, cfg RootConfig, res *ApplyResult) error

	mu sync.Mutex
}

func (r *Root) log() *slog.Logger {
	if r.Log != nil {
		return r.Log
	}
	return slog.Default()
}

func (r *Root) stateFile() string {
	if r.StateFile != "" {
		return r.StateFile
	}
	return filepath.Join(rootfile.RootStateDir, "mail.json")
}

func (r *Root) write(p string, data []byte, mode os.FileMode) error {
	if r.Write != nil {
		return r.Write(p, data, mode)
	}
	if err := rootfile.EnsureRootDir(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return rootfile.WriteAtomic(p, data, mode)
}

func (r *Root) chown(p string, uid, gid int) error {
	if r.Chown != nil {
		return r.Chown(p, uid, gid)
	}
	return os.Lchown(p, uid, gid)
}

func (r *Root) lookupUser(name string) (int, int, error) {
	if r.LookupUser != nil {
		return r.LookupUser(name)
	}
	u, err := user.Lookup(name)
	if err != nil {
		return 0, 0, fmt.Errorf("the system account %s is missing (is the mail server installed?): %w", name, err)
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	return uid, gid, nil
}

func (r *Root) lookupGroup(name string) (int, error) {
	if r.LookupGrp != nil {
		return r.LookupGrp(name)
	}
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0, fmt.Errorf("the system group %s is missing (is the mail server installed?): %w", name, err)
	}
	return strconv.Atoi(g.Gid)
}

func (r *Root) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return sysexec.Output(ctx, r.Runner, name, args...)
}

// dataset makes sure <pool>/mail exists and is mounted, and returns its
// mountpoint.
func (r *Root) dataset(ctx context.Context, pool string) (string, error) {
	if r.Dataset != nil {
		return r.Dataset(ctx, pool)
	}
	ds := pool + "/mail"
	out, err := r.run(ctx, "zfs", "get", "-H", "-p", "-o", "value", "mountpoint,mounted,"+PropMail, ds)
	if err != nil {
		var ce *sysexec.CommandError
		if !errors.As(err, &ce) || !strings.Contains(string(ce.Result.Stderr), "does not exist") {
			return "", err
		}
		// A dataset of its own: no devices, setuid or programs, and the
		// pool's own compression (lz4 when it has none).
		if _, err := r.run(ctx, "zpool", "list", "-H", "-o", "name", pool); err != nil {
			return "", invalid("the pool %s isn't available", pool)
		}
		if _, err := r.run(ctx, "zfs", "create", "-o", PropMail+"=1", "-o", "devices=off", "-o", "setuid=off",
			"-o", "exec=off", "-o", "xattr=sa", "-o", "atime=off", ds); err != nil {
			return "", err
		}
		if out, err = r.run(ctx, "zfs", "get", "-H", "-p", "-o", "value", "mountpoint,mounted,"+PropMail, ds); err != nil {
			return "", err
		}
	}
	f := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(f) != 3 {
		return "", fmt.Errorf("unexpected zfs output for %s", ds)
	}
	if strings.TrimSpace(f[2]) != "1" {
		return "", invalid("%s exists but wasn't made by HardyOS's mail server; rename or remove it first", ds)
	}
	if strings.TrimSpace(f[1]) != "yes" {
		if _, err := r.run(ctx, "zfs", "mount", ds); err != nil {
			return "", fmt.Errorf("%s isn't mounted: %w", ds, err)
		}
	}
	mp := strings.TrimSpace(f[0])
	if !filepath.IsAbs(mp) || filepath.Clean(mp) != mp || mp == "/" {
		return "", fmt.Errorf("%s has no usable mountpoint (%q)", ds, mp)
	}
	return mp, nil
}

// ensureDir makes dir (one level, never through a link) with the owner
// and mode given, fixing them when it exists.
func (r *Root) ensureDir(dir string, mode os.FileMode, uid, gid int) error {
	st, err := os.Lstat(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err := os.Mkdir(dir, mode); err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
		st, err = os.Lstat(dir)
		if err != nil {
			return err
		}
	case err != nil:
		return err
	}
	if !st.IsDir() {
		return fmt.Errorf("%s isn't a folder", dir)
	}
	if r.Chown != nil {
		if err := r.Chown(dir, uid, gid); err != nil {
			return err
		}
		return nil
	}
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("opening %s: %w", dir, err)
	}
	defer unix.Close(fd)
	if err := unix.Fchown(fd, uid, gid); err != nil {
		return err
	}
	return unix.Fchmod(fd, uint32(mode.Perm()))
}

// Layout of the mail dataset.
func (r *Root) layout(e Env, rad, rspamdGID int) error {
	type d struct {
		path     string
		mode     os.FileMode
		uid, gid int
	}
	for _, x := range []d{
		{e.MailRoot, 0o755, 0, 0},
		{e.VMailDir(), 0o700, e.VMailUID, e.VMailGID},
		{e.KeysDir(), 0o711, 0, 0},
		{e.DKIMDir(), 0o750, 0, rspamdGID},
		{e.TLSDir(), 0o700, 0, 0},
		{e.RadicaleDir(), 0o750, rad, rad},
		{filepath.Join(e.RadicaleDir(), "collections"), 0o750, rad, rad},
	} {
		if err := r.ensureDir(x.path, x.mode, x.uid, x.gid); err != nil {
			return err
		}
	}
	return nil
}

func (r *Root) env(ctx context.Context, pool string) (Env, error) {
	mp, err := r.dataset(ctx, pool)
	if err != nil {
		return Env{}, err
	}
	uid, gid, err := r.lookupUser(VMailUser)
	if err != nil {
		return Env{}, err
	}
	_, v6err := os.Stat("/proc/net/if_inet6")
	return Env{MailRoot: mp, VMailUID: uid, VMailGID: gid, NoIPv6: v6err != nil, DovecotLog: r.DovecotLog}, nil
}

// ApplyResult says what's running.
type ApplyResult struct {
	Services []string          `json:"services"`
	DKIM     map[string]string `json:"dkim"` // domain -> public key (base64 DER)
	Warnings []string          `json:"warnings"`
}

// Apply renders and checks the configuration, starts the services and
// remembers the setup for the next start.
func (r *Root) Apply(ctx context.Context, a ApplyArgs) (*ApplyResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.apply(ctx, a, true)
}

func (r *Root) apply(ctx context.Context, a ApplyArgs, save bool) (*ApplyResult, error) {
	cfg, err := a.Config.Normalize(a.Secrets)
	if err != nil {
		return nil, err
	}
	e, err := r.env(ctx, cfg.Pool)
	if err != nil {
		return nil, err
	}
	radUID, _, err := r.lookupUser("radicale")
	if err != nil {
		return nil, err
	}
	rspamdGID, err := r.lookupGroup("_rspamd")
	if err != nil {
		return nil, err
	}
	if err := r.layout(e, radUID, rspamdGID); err != nil {
		return nil, err
	}
	res := &ApplyResult{DKIM: map[string]string{}, Warnings: []string{}, Services: []string{}}
	for _, d := range cfg.Domains {
		pub, err := r.ensureDKIM(e, d.Name, d.Selector, rspamdGID)
		if err != nil {
			return nil, err
		}
		res.DKIM[d.Name] = pub
	}
	if err := r.ensureTLS(e, cfg.Hostname); err != nil {
		return nil, err
	}
	if err := r.installTLS(e); err != nil {
		return nil, err
	}
	if cfg.SharedCalendar {
		if err := r.familyCollections(e, radUID); err != nil {
			res.Warnings = append(res.Warnings, "family calendar: "+err.Error())
		}
	}
	// Write, keeping what was there so a configuration the programs refuse
	// is put back.
	files := Render(cfg, a.Secrets, e)
	prev := map[string][]byte{}
	for _, f := range files {
		if b, err := os.ReadFile(f.Path); err == nil {
			prev[f.Path] = b
		}
	}
	restore := func() {
		for _, f := range files {
			if b, ok := prev[f.Path]; ok {
				_ = r.write(f.Path, b, os.FileMode(f.Mode))
			} else {
				_ = os.Remove(f.Path)
			}
		}
	}
	for _, f := range files {
		if err := r.write(f.Path, []byte(f.Content), os.FileMode(f.Mode)); err != nil {
			restore()
			return nil, fmt.Errorf("writing %s: %w", f.Path, err)
		}
		if f.Group != "" {
			gid, err := r.lookupGroup(f.Group)
			if err != nil {
				restore()
				return nil, err
			}
			if err := r.chown(f.Path, 0, gid); err != nil {
				restore()
				return nil, err
			}
		}
	}
	if !r.SkipChecks {
		if err := r.check(ctx); err != nil {
			restore()
			return nil, err
		}
	}
	start := r.start
	if r.StartServices != nil {
		start = r.StartServices
	}
	if err := start(ctx, cfg, res); err != nil {
		return nil, err
	}
	if save {
		b, _ := json.Marshal(ApplyArgs{Config: cfg, Secrets: a.Secrets})
		if err := r.write(r.stateFile(), b, 0o600); err != nil {
			res.Warnings = append(res.Warnings, "couldn't remember the setup for the next start: "+err.Error())
		}
	}
	return res, nil
}

// check asks each program whether it accepts its configuration.
func (r *Root) check(ctx context.Context) error {
	for _, c := range [][]string{
		{"postfix", "check"},
		{"doveconf", "-n"},
		{"rspamadm", "configtest"},
		{"nft", "-c", "-f", NFTFile},
	} {
		if _, err := r.run(ctx, c[0], c[1:]...); err != nil {
			return fmt.Errorf("the generated configuration was refused by %s: %w", c[0], err)
		}
	}
	for _, s := range []string{"junk.sieve", "report-spam.sieve", "report-ham.sieve"} {
		if _, err := r.run(ctx, "sievec", filepath.Join(DovecotDir, "sieve", s)); err != nil {
			return fmt.Errorf("compiling %s: %w", s, err)
		}
	}
	return nil
}

func (r *Root) systemctl(ctx context.Context, args ...string) error {
	_, err := r.run(ctx, "systemctl", args...)
	return err
}

func (r *Root) start(ctx context.Context, cfg RootConfig, res *ApplyResult) error {
	if _, err := r.run(ctx, "nft", "-f", NFTFile); err != nil {
		return fmt.Errorf("firewall: %w", err)
	}
	_ = r.systemctl(ctx, "daemon-reload")
	if err := r.ensureRedisDir(); err != nil {
		return err
	}
	units := slices.Clone(coreUnits)
	if cfg.ClamAV {
		units = append(clamavUnits, units...)
	} else {
		_ = r.systemctl(ctx, append([]string{"stop"}, clamavUnits...)...)
	}
	for _, u := range units {
		verb := "restart"
		if u == "postfix.service" || u == "dovecot.service" {
			verb = "reload-or-restart"
		}
		if err := r.systemctl(ctx, verb, u); err != nil {
			if strings.HasPrefix(u, "clamav") {
				// The virus database may not be downloaded yet.
				res.Warnings = append(res.Warnings, u+" didn't start: "+err.Error())
				continue
			}
			return fmt.Errorf("starting %s: %w", u, err)
		}
		res.Services = append(res.Services, u)
	}
	return nil
}

func (r *Root) ensureRedisDir() error {
	if r.Chown != nil {
		return nil
	}
	uid, gid, err := r.lookupUser("redis")
	if err != nil {
		return err
	}
	return r.ensureDir(RedisDataDir, 0o750, uid, gid)
}

// Stop turns the mail server off (data stays).
func (r *Root) Stop(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	all := append(slices.Clone(coreUnits), clamavUnits...)
	slices.Reverse(all)
	_ = r.systemctl(ctx, append([]string{"stop"}, all...)...)
	_, _ = r.run(ctx, "nft", "delete", "table", "inet", "hardyos_mail")
	if err := os.Remove(r.stateFile()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// OnStart brings the mail server back after a restart or an update: once
// the pool with the mail dataset is mounted, everything is rendered again
// from the saved setup and started. The services are never enabled at boot
// on their own (they'd start with an empty folder where the pool belongs).
func (r *Root) OnStart(ctx context.Context) {
	b, err := rootfile.ReadFile(r.stateFile())
	if err != nil {
		if !rootfile.IsNotExist(err) {
			r.log().Warn("mail: saved setup unreadable", "err", err)
		}
		return
	}
	var a ApplyArgs
	if err := json.Unmarshal(b, &a); err != nil {
		r.log().Warn("mail: saved setup unreadable", "err", err)
		return
	}
	for i := 0; i < 60; i++ {
		r.mu.Lock()
		_, err := r.apply(ctx, a, false)
		r.mu.Unlock()
		if err == nil {
			r.log().Info("mail server started")
			return
		}
		r.log().Warn("mail: not started yet", "err", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Second):
		}
	}
}

// ---- DKIM ----

// dkimPublic returns the base64 DER public key of a PEM private key.
func dkimPublic(keyPEM []byte) (string, error) {
	blk, _ := pem.Decode(keyPEM)
	if blk == nil {
		return "", errors.New("not a PEM key")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		if k1, err1 := x509.ParsePKCS1PrivateKey(blk.Bytes); err1 == nil {
			k = k1
		} else {
			return "", err
		}
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return "", errors.New("the DKIM key isn't RSA")
	}
	der, err := x509.MarshalPKIXPublicKey(&rk.PublicKey)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

// ensureDKIM makes the domain's key when there's none and returns its
// public half.
func (r *Root) ensureDKIM(e Env, domain, selector string, rspamdGID int) (string, error) {
	p := e.DKIMKeyPath(domain, selector)
	b, err := readNoFollow(p, 64<<10)
	if err == nil {
		return dkimPublic(b)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return "", err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := writeNew(p, keyPEM, 0o640); err != nil {
		return "", err
	}
	if err := r.chown(p, 0, rspamdGID); err != nil {
		return "", err
	}
	return dkimPublic(keyPEM)
}

// DKIMArgs names a domain's key.
type DKIMArgs struct {
	Pool     string `json:"pool"`
	Domain   string `json:"domain"`
	Selector string `json:"selector"`
}

// DKIMResult is a domain key's public half (base64 DER, the DNS p= value).
type DKIMResult struct {
	Domain    string `json:"domain"`
	Selector  string `json:"selector"`
	PublicKey string `json:"publicKey"`
}

// DKIM makes (or reads) a domain's DKIM key. A new selector is a new key:
// that's how keys are rotated (publish the new record, then switch).
func (r *Root) DKIM(ctx context.Context, a DKIMArgs) (*DKIMResult, error) {
	if !ValidDomain(a.Domain) || !selectorRE.MatchString(a.Selector) || !poolRE.MatchString(a.Pool) {
		return nil, invalid("invalid domain, selector or pool")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	e, err := r.env(ctx, a.Pool)
	if err != nil {
		return nil, err
	}
	rad, _, err := r.lookupUser("radicale")
	if err != nil {
		return nil, err
	}
	g, err := r.lookupGroup("_rspamd")
	if err != nil {
		return nil, err
	}
	if err := r.layout(e, rad, g); err != nil {
		return nil, err
	}
	pub, err := r.ensureDKIM(e, a.Domain, a.Selector, g)
	if err != nil {
		return nil, err
	}
	return &DKIMResult{Domain: a.Domain, Selector: a.Selector, PublicKey: pub}, nil
}

// ---- TLS ----

// ensureTLS makes a self-signed certificate for hostname when there's no
// certificate yet, so the services can start before ACME (or an upload)
// gives them a trusted one.
func (r *Root) ensureTLS(e Env, hostname string) error {
	if _, err := os.Lstat(e.TLSChain()); err == nil {
		if _, err := os.Lstat(e.TLSKey()); err == nil {
			return nil
		}
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hostname, Organization: []string{"HardyOS (self-signed)"}},
		DNSNames:     []string{hostname},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(2, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		return err
	}
	kder, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return err
	}
	if err := r.write(e.TLSKey(), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}), 0o600); err != nil {
		return err
	}
	return r.write(e.TLSChain(), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}

// installTLS copies the pool's certificate and key to /run for Postfix
// and Dovecot (read by root before they drop privileges).
func (r *Root) installTLS(e Env) error {
	key, err := readNoFollow(e.TLSKey(), 64<<10)
	if err != nil {
		return err
	}
	chain, err := readNoFollow(e.TLSChain(), 256<<10)
	if err != nil {
		return err
	}
	if _, err := matchKey(key, chain); err != nil {
		return err
	}
	if r.Write != nil {
		_ = r.write(filepath.Join(RunTLSDir, "key.pem"), key, 0o600)
		return r.write(filepath.Join(RunTLSDir, "fullchain.pem"), chain, 0o644)
	}
	if err := rootfile.EnsureRootDir("/run/hardyos-mail", 0o755); err != nil {
		return err
	}
	if err := rootfile.EnsureRootDir(RunTLSDir, 0o700); err != nil {
		return err
	}
	if err := rootfile.WriteAtomic(filepath.Join(RunTLSDir, "key.pem"), key, 0o600); err != nil {
		return err
	}
	return rootfile.WriteAtomic(filepath.Join(RunTLSDir, "fullchain.pem"), chain, 0o644)
}

// matchKey checks that chain's first certificate is for key and returns
// the parsed chain.
func matchKey(keyPEM, chainPEM []byte) ([]*x509.Certificate, error) {
	blk, _ := pem.Decode(keyPEM)
	if blk == nil {
		return nil, errors.New("the TLS key isn't PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		if ek, err2 := x509.ParseECPrivateKey(blk.Bytes); err2 == nil {
			k = ek
		} else if rk, err3 := x509.ParsePKCS1PrivateKey(blk.Bytes); err3 == nil {
			k = rk
		} else {
			return nil, fmt.Errorf("the TLS key can't be read: %w", err)
		}
	}
	certs, err := parseChain(chainPEM)
	if err != nil {
		return nil, err
	}
	pk, ok := k.(crypto.Signer)
	if !ok {
		return nil, errors.New("unsupported key")
	}
	pd, err := x509.MarshalPKIXPublicKey(pk.Public())
	if err != nil {
		return nil, err
	}
	cd, err := x509.MarshalPKIXPublicKey(certs[0].PublicKey)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(pd, cd) {
		return nil, invalid("the certificate isn't for this key")
	}
	return certs, nil
}

func parseChain(chainPEM []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := chainPEM
	for len(certs) < 10 {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			return nil, invalid("the certificate file holds a %s", blk.Type)
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, invalid("a certificate can't be read: %v", err)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, invalid("no certificate found")
	}
	return certs, nil
}

// CSRArgs asks for a certificate request for the mail server's names.
type CSRArgs struct {
	Pool  string   `json:"pool"`
	Names []string `json:"names"`
}

// CSRResult is a PKCS#10 request (base64 DER) for a new key root keeps.
type CSRResult struct {
	CSR string `json:"csr"`
}

// CSR makes a new key (kept by root as the pending key) and a request for
// it: the private key never leaves root, hardyd only does ACME.
func (r *Root) CSR(ctx context.Context, a CSRArgs) (*CSRResult, error) {
	if !poolRE.MatchString(a.Pool) || len(a.Names) == 0 || len(a.Names) > 10 {
		return nil, invalid("invalid pool or names")
	}
	for _, n := range a.Names {
		if !ValidDomain(n) {
			return nil, invalid("%q isn't a host name", n)
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	e, err := r.env(ctx, a.Pool)
	if err != nil {
		return nil, err
	}
	if err := r.ensureDir(e.KeysDir(), 0o711, 0, 0); err != nil {
		return nil, err
	}
	if err := r.ensureDir(e.TLSDir(), 0o700, 0, 0); err != nil {
		return nil, err
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: a.Names[0]}, DNSNames: a.Names,
	}, k)
	if err != nil {
		return nil, err
	}
	kder, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	if err := r.write(filepath.Join(e.TLSDir(), "pending-key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}), 0o600); err != nil {
		return nil, err
	}
	return &CSRResult{CSR: base64.StdEncoding.EncodeToString(der)}, nil
}

// InstallArgs installs a certificate chain (PEM). With Key (an uploaded
// key, PEM) it is installed with that key; without, the chain must be for
// the pending key CSR made.
type InstallArgs struct {
	Pool     string `json:"pool"`
	Hostname string `json:"hostname"`
	Chain    string `json:"chain"`
	Key      string `json:"key,omitempty"`
}

// CertInfo describes the installed certificate.
type CertInfo struct {
	Names       []string  `json:"names"`
	Issuer      string    `json:"issuer"`
	NotAfter    time.Time `json:"notAfter"`
	SelfSigned  bool      `json:"selfSigned"`
	Fingerprint string    `json:"fingerprint"` // SHA-256 of the leaf
	PEM         string    `json:"pem"`         // the leaf, for pinning on this server
}

func certInfo(certs []*x509.Certificate) *CertInfo {
	c := certs[0]
	sum := sha256.Sum256(c.Raw)
	return &CertInfo{
		Names: c.DNSNames, Issuer: c.Issuer.CommonName, NotAfter: c.NotAfter.UTC(),
		SelfSigned:  bytes.Equal(c.RawIssuer, c.RawSubject) && len(certs) == 1,
		Fingerprint: hex.EncodeToString(sum[:]),
		PEM:         string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})),
	}
}

// Install checks and installs a certificate, then reloads Postfix and
// Dovecot.
func (r *Root) Install(ctx context.Context, a InstallArgs) (*CertInfo, error) {
	if !poolRE.MatchString(a.Pool) || !ValidDomain(a.Hostname) || len(a.Chain) > 256<<10 || len(a.Key) > 64<<10 {
		return nil, invalid("invalid certificate request")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	e, err := r.env(ctx, a.Pool)
	if err != nil {
		return nil, err
	}
	pending := filepath.Join(e.TLSDir(), "pending-key.pem")
	key := []byte(a.Key)
	if a.Key == "" {
		if key, err = readNoFollow(pending, 64<<10); err != nil {
			return nil, invalid("there's no certificate request waiting for this certificate")
		}
	}
	certs, err := matchKey(key, []byte(a.Chain))
	if err != nil {
		return nil, err
	}
	leaf := certs[0]
	if err := leaf.VerifyHostname(a.Hostname); err != nil {
		return nil, invalid("the certificate isn't for %s", a.Hostname)
	}
	if time.Now().After(leaf.NotAfter) {
		return nil, invalid("the certificate has expired")
	}
	// Normalised PEM: only the certificates.
	var chain bytes.Buffer
	for _, c := range certs {
		_ = pem.Encode(&chain, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	if err := r.write(e.TLSKey(), key, 0o600); err != nil {
		return nil, err
	}
	if err := r.write(e.TLSChain(), chain.Bytes(), 0o644); err != nil {
		return nil, err
	}
	_ = os.Remove(pending)
	if err := r.installTLS(e); err != nil {
		return nil, err
	}
	for _, u := range []string{"postfix.service", "dovecot.service"} {
		if err := r.systemctl(ctx, "reload", u); err != nil {
			r.log().Warn("mail: reload after new certificate", "unit", u, "err", err)
		}
	}
	return certInfo(certs), nil
}

// ---- status, queue, sessions, mailboxes ----

// StatusArgs names the pool (for the certificate and space).
type StatusArgs struct {
	Pool string `json:"pool"`
}

// QueueItem is one queued message (postqueue -j).
type QueueItem struct {
	ID         string    `json:"id"`
	Queue      string    `json:"queue"` // active, deferred, hold, incoming
	ArrivedAt  time.Time `json:"arrivedAt"`
	Size       int64     `json:"size"`
	Sender     string    `json:"sender"`
	Recipients []string  `json:"recipients"`
	Reason     string    `json:"reason"`
}

// Status is what's running and waiting.
type Status struct {
	Services map[string]string `json:"services"` // unit -> active state
	Queue    []QueueItem       `json:"queue"`
	Cert     *CertInfo         `json:"cert,omitempty"`
	UsedMB   int64             `json:"usedMb"`
	Running  bool              `json:"running"`
}

// MaxQueueList bounds what Status lists.
const MaxQueueList = 200

// Status reports services, the queue and the certificate.
func (r *Root) Status(ctx context.Context, a StatusArgs) (*Status, error) {
	st := &Status{Services: map[string]string{}, Queue: []QueueItem{}}
	all := append(slices.Clone(coreUnits), clamavUnits...)
	out, _ := sysexec.Output(ctx, r.Runner, "systemctl", append([]string{"is-active"}, all...)...)
	states := strings.Fields(string(out))
	running := true
	for i, u := range all {
		s := "unknown"
		if i < len(states) {
			s = states[i]
		}
		st.Services[u] = s
		if !slices.Contains(clamavUnits, u) && s != "active" {
			running = false
		}
	}
	st.Running = running
	if q, err := sysexec.Output(ctx, r.Runner, "postqueue", "-j"); err == nil {
		st.Queue = ParseQueue(q, MaxQueueList)
	}
	if poolRE.MatchString(a.Pool) {
		if b, err := readNoFollow(filepath.Join(RunTLSDir, "fullchain.pem"), 256<<10); err == nil {
			if certs, err := parseChain(b); err == nil {
				st.Cert = certInfo(certs)
			}
		}
		if out, err := sysexec.Output(ctx, r.Runner, "zfs", "get", "-H", "-p", "-o", "value", "used", a.Pool+"/mail"); err == nil {
			n, _ := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
			st.UsedMB = n >> 20
		}
	}
	return st, nil
}

// ParseQueue reads postqueue -j (one JSON object per line).
func ParseQueue(out []byte, limit int) []QueueItem {
	items := []QueueItem{}
	for _, line := range bytes.Split(out, []byte("\n")) {
		if len(items) >= limit {
			break
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var raw struct {
			QueueName   string `json:"queue_name"`
			QueueID     string `json:"queue_id"`
			ArrivalTime int64  `json:"arrival_time"`
			MessageSize int64  `json:"message_size"`
			Sender      string `json:"sender"`
			Recipients  []struct {
				Address     string `json:"address"`
				DelayReason string `json:"delay_reason"`
			} `json:"recipients"`
		}
		if json.Unmarshal(line, &raw) != nil {
			continue
		}
		it := QueueItem{ID: raw.QueueID, Queue: raw.QueueName, ArrivedAt: time.Unix(raw.ArrivalTime, 0).UTC(),
			Size: raw.MessageSize, Sender: clipText(raw.Sender, 254), Recipients: []string{}}
		for _, rc := range raw.Recipients {
			if len(it.Recipients) < 20 {
				it.Recipients = append(it.Recipients, clipText(rc.Address, 254))
			}
			if it.Reason == "" && rc.DelayReason != "" {
				it.Reason = clipText(rc.DelayReason, 300)
			}
		}
		items = append(items, it)
	}
	return items
}

func clipText(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > n {
		return s[:n]
	}
	return s
}

// Flush retries every deferred message now.
func (r *Root) Flush(ctx context.Context) error {
	_, err := r.run(ctx, "postqueue", "-f")
	return err
}

// AddressArgs names one mailbox.
type AddressArgs struct {
	Address string `json:"address"`
}

// Kick ends a mailbox's open IMAP sessions and forgets its cached
// sign-ins: a person turned off loses access now, not when their app
// reconnects.
func (r *Root) Kick(ctx context.Context, a AddressArgs) error {
	if _, _, err := SplitAddress(a.Address); err != nil {
		return err
	}
	_, _ = r.run(ctx, "doveadm", "auth", "cache", "flush", a.Address)
	if _, err := r.run(ctx, "doveadm", "kick", a.Address); err != nil {
		var ce *sysexec.CommandError
		// Exit 68: nobody was signed in.
		if errors.As(err, &ce) && ce.Result.ExitCode == 68 {
			return nil
		}
		return err
	}
	return nil
}

// DeleteArgs deletes a mailbox's messages for good.
type DeleteArgs struct {
	Pool    string `json:"pool"`
	Address string `json:"address"`
	// Confirm must be the address typed again.
	Confirm string `json:"confirm"`
}

// DeleteMailbox removes a mailbox's folder (every message in it). Its
// address must have been removed from the configuration first.
func (r *Root) DeleteMailbox(ctx context.Context, a DeleteArgs) error {
	local, dom, err := SplitAddress(a.Address)
	if err != nil {
		return err
	}
	if a.Confirm != a.Address {
		return invalid("type the mailbox's address to confirm")
	}
	if !poolRE.MatchString(a.Pool) {
		return invalid("invalid pool")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if b, err := rootfile.ReadFile(r.stateFile()); err == nil {
		var cur ApplyArgs
		if json.Unmarshal(b, &cur) == nil && hasMailbox(cur.Config, a.Address) {
			return invalid("%s is still a mailbox; remove it from the mail server first", a.Address)
		}
	}
	e, err := r.env(ctx, a.Pool)
	if err != nil {
		return err
	}
	_ = r.kickLocked(ctx, a.Address)
	root, err := os.OpenRoot(e.VMailDir())
	if err != nil {
		return err
	}
	defer root.Close()
	if err := root.RemoveAll(filepath.Join(dom, local)); err != nil {
		return err
	}
	return nil
}

func (r *Root) kickLocked(ctx context.Context, addr string) error {
	_, _ = r.run(ctx, "doveadm", "auth", "cache", "flush", addr)
	_, _ = r.run(ctx, "doveadm", "kick", addr)
	return nil
}

// UsageArgs asks for mailbox sizes.
type UsageArgs struct {
	Addresses []string `json:"addresses"`
}

// Usage is one mailbox's quota use.
type Usage struct {
	Address string `json:"address"`
	UsedKB  int64  `json:"usedKb"`
	LimitKB int64  `json:"limitKb"` // 0: none
}

// Usage reads Dovecot's quota for each mailbox.
func (r *Root) Usage(ctx context.Context, a UsageArgs) ([]Usage, error) {
	out := []Usage{}
	if len(a.Addresses) > MaxMailboxes {
		return nil, invalid("too many mailboxes")
	}
	for _, addr := range a.Addresses {
		if _, _, err := SplitAddress(addr); err != nil {
			return nil, err
		}
		b, err := r.run(ctx, "doveadm", "-f", "tab", "quota", "get", "-u", addr)
		if err != nil {
			continue
		}
		out = append(out, ParseQuota(addr, b))
	}
	return out, nil
}

// ParseQuota reads `doveadm -f tab quota get` output.
func ParseQuota(addr string, b []byte) Usage {
	u := Usage{Address: addr}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) < 2 {
		return u
	}
	head := strings.Split(lines[0], "\t")
	idx := func(name string) int { return slices.Index(head, name) }
	for _, l := range lines[1:] {
		f := strings.Split(l, "\t")
		if i := idx("type"); i < 0 || i >= len(f) || !strings.EqualFold(f[i], "STORAGE") {
			continue
		}
		if i := idx("value"); i >= 0 && i < len(f) {
			u.UsedKB, _ = strconv.ParseInt(f[i], 10, 64)
		}
		if i := idx("limit"); i >= 0 && i < len(f) {
			u.LimitKB, _ = strconv.ParseInt(f[i], 10, 64)
		}
	}
	return u
}

// familyCollections makes the shared calendar and address book in
// Radicale's storage when they're missing.
func (r *Root) familyCollections(e Env, rad int) error {
	base := filepath.Join(e.RadicaleDir(), "collections", "collection-root")
	fam := filepath.Join(base, "family")
	for _, d := range []string{base, fam, filepath.Join(fam, "calendar"), filepath.Join(fam, "contacts")} {
		if err := r.ensureDir(d, 0o750, rad, rad); err != nil {
			return err
		}
	}
	props := map[string]string{
		"calendar": `{"C:supported-calendar-component-set": "VEVENT,VTODO", "D:displayname": "Family", "ICAL:calendar-color": "#22D3EE", "tag": "VCALENDAR"}`,
		"contacts": `{"D:displayname": "Family contacts", "tag": "VADDRESSBOOK"}`,
	}
	for name, p := range props {
		fp := filepath.Join(fam, name, ".Radicale.props")
		if _, err := os.Lstat(fp); err == nil {
			continue
		}
		if err := writeNew(fp, []byte(p), 0o640); err != nil {
			return err
		}
		if err := r.chown(fp, rad, rad); err != nil {
			return err
		}
	}
	return nil
}

// readNoFollow reads a regular file without following a link at its last
// component, up to max bytes.
func readNoFollow(p string, max int64) ([]byte, error) {
	f, err := os.OpenFile(p, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > max {
		return nil, fmt.Errorf("%s isn't a regular file of at most %d bytes", p, max)
	}
	b := make([]byte, st.Size())
	_, err = f.ReadAt(b, 0)
	if err != nil && st.Size() > 0 {
		return nil, err
	}
	return b, nil
}

// writeNew creates a file that must not exist yet (never through a link).
func writeNew(p string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
