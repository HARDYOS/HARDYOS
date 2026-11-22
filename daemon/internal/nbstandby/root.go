package nbstandby

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/rootfile"
	"golang.org/x/crypto/ssh"
)

// Root is hardyd-priv's side of the standby (decisions 421-427): the VPS
// connection and root's SSH key, the sealed snapshots, staging a take-over
// into the app and hand-back. Its state lives in Dir, a root-only folder
// inside the keys folder (not in settings backups, kept across boot
// environments); hardyd never sees the key or a snapshot's contents.
type Root struct {
	// Dir is root's folder (zfs.KeyDir/netbird-standby).
	Dir string
	// Key is root's own sealing key (RootKeyFor(keys, "netbird-standby")).
	Key func() ([]byte, error)
	// Remote turns a target into a Remote (tests: a fake VPS); default the
	// target itself (SSH).
	Remote func(SSHTarget) Remote
	// Apps finds the netbird-standby app.
	Apps AppData
	// Net applies the firewall table and the hosts entry.
	Net NetApplier
	// Now is the clock (tests).
	Now func() time.Time
	Log *slog.Logger
	// DNSName is the NetBird standby name adopted in root's DNS state ("" when
	// none): the hostname can't move away from it (decision 424).
	DNSName func() string
	// DNSBound is the binding recorded when the name was adopted (false
	// when none): a take-over is staged only while it equals the current
	// one.
	DNSBound func() (Binding, bool)

	mu     sync.Mutex // state file
	syncMu sync.Mutex // one transfer at a time
}

// AppData is what root needs to know about the installed app.
type AppData interface {
	// StandbyApp returns the app's data folder (the folder its compose file
	// binds from), whether any of its containers runs, and whether root
	// itself verified it as the shipped catalog package. err wraps
	// ErrNoApp when it isn't installed.
	StandbyApp(ctx context.Context) (dir string, running, catalog bool, err error)
}

// ErrNoApp means the netbird-standby app isn't installed.
var ErrNoApp = errors.New("the NetBird Standby app isn't installed")

// NetApplier sets the firewall table and hosts entry (System in production).
type NetApplier interface {
	Apply(ctx context.Context, open bool, host string) error
	Remove(ctx context.Context) error
}

// Modes.
const (
	ModeStandby   = "standby"
	ModeTakenOver = "takenover"
)

// KeepSnapshots is how many sealed snapshots root keeps.
const KeepSnapshots = 3

const stateFile = "state.json"

// Problem is an error to show as it is (bad arguments, a refused step).
type Problem struct{ Msg string }

func (p *Problem) Error() string { return p.Msg }

func problemf(format string, a ...any) error { return &Problem{Msg: fmt.Sprintf(format, a...)} }

type state struct {
	V          int              `json:"v"`
	VPSHost    string           `json:"vpsHost,omitempty"`
	VPSPort    int              `json:"vpsPort,omitempty"`
	VPSUser    string           `json:"vpsUser,omitempty"`
	HostKey    string           `json:"hostKey,omitempty"`
	Hostname   string           `json:"hostname,omitempty"`
	KeySealed  []byte           `json:"keySealed,omitempty"`
	PublicKey  string           `json:"publicKey,omitempty"`
	KeyCreated time.Time        `json:"keyCreated,omitzero"`
	Snapshots  []SnapshotRecord `json:"snapshots,omitempty"`
	LastTry    time.Time        `json:"lastTry,omitzero"`
	LastOK     time.Time        `json:"lastOk,omitzero"`
	LastError  string           `json:"lastError,omitempty"`
	Mode       string           `json:"mode,omitempty"`
	Staged     string           `json:"staged,omitempty"`
	TakenOver  time.Time        `json:"takenOver,omitzero"`
	NetOpen    bool             `json:"netOpen,omitempty"`
	// PublicIPv4/IPv6 are the only addresses DNS may point the standby name
	// at (set with the hostname typed, never while taken over).
	PublicIPv4 string `json:"publicIPv4,omitempty"`
	PublicIPv6 string `json:"publicIPv6,omitempty"`
	// From are the addresses HardyOS connects from (the key's from=).
	From []string `json:"from,omitempty"`
	// Handback is the sealed copy of what the last hand-back sent, kept
	// until the next good sync.
	Handback string `json:"handback,omitempty"`
	// Fences are the fences made while not taken over (the last 24 h).
	Fences []time.Time `json:"fences,omitempty"`
	// Returned: during this take-over the VPS was unfenced or got the state
	// back, so the fence is no longer renewed (until the next take-over).
	Returned bool `json:"returned,omitempty"`
}

// FenceTTL is how long a fence lasts on the VPS unless renewed; HardyOS
// renews it every FenceRenew while it has taken over (decision 426).
// MaxFences fences a day may be made without a take-over following, so a
// compromised hardyd can't keep the VPS's server stopped.
const (
	FenceTTL   = 2 * time.Hour
	FenceRenew = 20 * time.Minute
	MaxFences  = 3
)

// SnapshotRecord is one sealed snapshot.
type SnapshotRecord struct {
	ID     string    `json:"id"`
	At     time.Time `json:"at"`
	Sealed int64     `json:"sealedBytes"`
	Info   Info      `json:"info"`
}

// Status is what hardyd may know.
type Status struct {
	Configured  bool             `json:"configured"`
	VPSHost     string           `json:"vpsHost"`
	VPSPort     int              `json:"vpsPort"`
	VPSUser     string           `json:"vpsUser"`
	HostKey     string           `json:"hostKey"`
	HostKeyFP   string           `json:"hostKeyFingerprint"`
	Hostname    string           `json:"hostname"`
	PublicKey   string           `json:"publicKey"`
	KeyCreated  time.Time        `json:"keyCreated,omitzero"`
	Snapshots   []SnapshotRecord `json:"snapshots"`
	LastTry     time.Time        `json:"lastTry,omitzero"`
	LastOK      time.Time        `json:"lastOk,omitzero"`
	LastError   string           `json:"lastError,omitempty"`
	Mode        string           `json:"mode"`
	Staged      string           `json:"staged,omitempty"`
	TakenOverAt time.Time        `json:"takenOverAt,omitzero"`
	NetworkOpen bool             `json:"networkOpen"`
	PublicIPv4  string           `json:"publicIPv4"`
	PublicIPv6  string           `json:"publicIPv6"`
	From        []string         `json:"from"`
	// HandbackCopy: a sealed copy of the last hand-back is kept.
	HandbackCopy bool `json:"handbackCopy"`
}

// ConfigureArgs sets the VPS connection.
type ConfigureArgs struct {
	VPSHost  string `json:"vpsHost"`
	VPSPort  int    `json:"vpsPort"`
	VPSUser  string `json:"vpsUser"`
	HostKey  string `json:"hostKey"`
	Hostname string `json:"hostname"`
	// From are the addresses HardyOS connects from (at most 8).
	From []string `json:"from"`
	// NewKey makes a new SSH key (the VPS script must be run again).
	NewKey bool `json:"newKey"`
}

// AddressArgs sets this server's public addresses; Confirm is the hostname.
type AddressArgs struct {
	IPv4    string `json:"ipv4"`
	IPv6    string `json:"ipv6"`
	Confirm string `json:"confirm"`
}

// ScriptResult is the VPS script root made.
type ScriptResult struct {
	Script      string `json:"script"`
	Fingerprint string `json:"fingerprint"`
}

// ConfirmArgs carries a typed confirmation (the NetBird hostname).
type ConfirmArgs struct {
	Confirm string `json:"confirm"`
}

// NetworkArgs opens or closes the standby's ports.
type NetworkArgs struct {
	Open bool `json:"open"`
}

// VPSStatus is what the VPS's status verb says.
type VPSStatus struct {
	Running        bool   `json:"running"`
	Version        string `json:"version"`
	Digest         string `json:"digest"`
	Image          string `json:"image"`
	Hostname       string `json:"hostname"`
	RestoreAllowed bool   `json:"restoreAllowed"`
	// RestoreArmedUntil: hand-back was armed on the VPS until then (one
	// use; "" when not armed).
	RestoreArmedUntil string `json:"restoreArmedUntil"`
	// HandbackInstalled: the script was installed with --allow-handback.
	HandbackInstalled bool `json:"handbackInstalled"`
	// Fenced: HardyOS stopped the VPS's server for a take-over, until
	// FencedUntil unless renewed (decision 426).
	Fenced      bool   `json:"fenced"`
	FencedUntil string `json:"fencedUntil,omitempty"`
	Time        string `json:"time"`
}

// StageResult says what was staged.
type StageResult struct {
	Snapshot SnapshotRecord `json:"snapshot"`
}

// HandbackResult is what the VPS said.
type HandbackResult struct {
	Message string `json:"message"`
	Bytes   int64  `json:"bytes"`
}

func (r *Root) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}

func (r *Root) log() *slog.Logger {
	if r.Log != nil {
		return r.Log
	}
	return slog.Default()
}

func (r *Root) load() (*state, error) {
	if err := rootfile.EnsureRootDir(r.Dir, 0o700); err != nil {
		return nil, err
	}
	b, err := rootfile.ReadFileInRootDir(filepath.Join(r.Dir, stateFile))
	if errors.Is(err, fs.ErrNotExist) {
		return &state{V: 1, Mode: ModeStandby}, nil
	}
	if err != nil {
		return nil, err
	}
	var st state
	if err := json.Unmarshal(b, &st); err != nil || st.V != 1 {
		return nil, errors.New("the standby's state file isn't HardyOS's")
	}
	if st.Mode == "" {
		st.Mode = ModeStandby
	}
	return &st, nil
}

func (r *Root) save(st *state) error {
	st.V = 1
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return rootfile.WriteInRootDir(filepath.Join(r.Dir, stateFile), b, 0o600, 0o700)
}

func (st *state) status() *Status {
	out := &Status{Configured: st.VPSHost != "" && st.Hostname != "" && len(st.KeySealed) > 0 && st.HostKey != "",
		VPSHost: st.VPSHost, VPSPort: st.VPSPort, VPSUser: st.VPSUser, HostKey: st.HostKey, Hostname: st.Hostname,
		PublicKey: st.PublicKey, KeyCreated: st.KeyCreated, Snapshots: append([]SnapshotRecord{}, st.Snapshots...),
		LastTry: st.LastTry, LastOK: st.LastOK, LastError: st.LastError, Mode: st.Mode, Staged: st.Staged,
		TakenOverAt: st.TakenOver, NetworkOpen: st.NetOpen, PublicIPv4: st.PublicIPv4, PublicIPv6: st.PublicIPv6,
		From: append([]string{}, st.From...), HandbackCopy: st.Handback != ""}
	if pk, err := ParseHostKey(st.HostKey); err == nil {
		out.HostKeyFP = Fingerprint(pk)
	}
	return out
}

// Status reports the state.
func (r *Root) Status(ctx context.Context) (*Status, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	st, err := r.load()
	if err != nil {
		return nil, err
	}
	return st.status(), nil
}

func keyAAD() []byte { return []byte("hardyos nbstandby ssh key v1") }

// Configure saves the VPS connection (refused while taken over). A new
// hostname drops the snapshots of the old one.
func (r *Root) Configure(ctx context.Context, a ConfigureArgs) (*Status, error) {
	host := strings.ToLower(strings.TrimSpace(a.VPSHost))
	user := strings.TrimSpace(a.VPSUser)
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(a.Hostname), "."))
	if user == "" {
		user = VPSUser
	}
	port := a.VPSPort
	if port == 0 {
		port = 22
	}
	switch {
	case !ValidVPSHost(host):
		return nil, problemf("%q isn't a host name or address", clip(a.VPSHost, 80))
	case port < 1 || port > 65535:
		return nil, problemf("the SSH port must be 1-65535")
	case !ValidVPSUser(user):
		return nil, problemf("%q isn't a user name", clip(a.VPSUser, 40))
	case !ValidHostname(name):
		return nil, problemf("%q isn't a host name like vpn.example.net", clip(a.Hostname, 80))
	case host == name:
		// During a take-over the name leads here, never to the VPS.
		return nil, problemf("the VPS's SSH address can't be the NetBird name itself (it points here during a take-over): use the VPS's own name or address")
	}
	from, err := CanonicalFrom(a.From)
	if err != nil {
		return nil, &Problem{Msg: err.Error()}
	}
	a.From = from
	if r.DNSName != nil {
		if adopted := r.DNSName(); adopted != "" && adopted != name {
			return nil, problemf("HardyOS manages %s in Cloudflare: stop managing it first (step 4) to use another name", adopted)
		}
	}
	hk, err := ParseHostKey(a.HostKey)
	if err != nil {
		return nil, &Problem{Msg: err.Error()}
	}
	r.syncMu.Lock()
	defer r.syncMu.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	st, err := r.load()
	if err != nil {
		return nil, err
	}
	if st.Mode == ModeTakenOver {
		return nil, problemf("HardyOS has taken over: hand back first")
	}
	if len(st.KeySealed) == 0 || a.NewKey {
		seed, pub, err := NewKey()
		if err != nil {
			return nil, err
		}
		k, err := r.Key()
		if err != nil {
			return nil, err
		}
		sealed, err := gcmSeal(k, seed, keyAAD())
		if err != nil {
			return nil, err
		}
		st.KeySealed, st.PublicKey, st.KeyCreated = sealed, pub, r.now()
	}
	newHostKey := strings.TrimSpace(string(marshalKey(hk)))
	if (st.Hostname != "" && st.Hostname != name) || (st.VPSHost != "" && (st.VPSHost != host || st.VPSPort != port)) ||
		(st.HostKey != "" && st.HostKey != newHostKey) {
		// Copies of another name, or from another server (or one whose
		// key changed), are never staged.
		r.dropSnapshots(st, nil)
		st.LastOK, st.LastError = time.Time{}, ""
	}
	st.VPSHost, st.VPSPort, st.VPSUser, st.Hostname = host, port, user, name
	st.HostKey = newHostKey
	st.From = a.From
	if err := r.save(st); err != nil {
		return nil, err
	}
	r.applyNet(ctx, st)
	return st.status(), nil
}

// Address sets the public addresses DNS may point the standby name at
// (decision 424): the hostname typed, never while taken over.
func (r *Root) Address(ctx context.Context, a AddressArgs) (*Status, error) {
	v4, v6 := strings.TrimSpace(a.IPv4), strings.TrimSpace(a.IPv6)
	if v4 != "" && !PublicAddr(v4, true) {
		return nil, problemf("%q isn't a public IPv4 address", clip(v4, 60))
	}
	if v6 != "" && !PublicAddr(v6, false) {
		return nil, problemf("%q isn't a public IPv6 address", clip(v6, 60))
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	st, err := r.load()
	if err != nil {
		return nil, err
	}
	if st.Mode == ModeTakenOver {
		return nil, problemf("HardyOS has taken over: hand back first")
	}
	if st.Hostname == "" || strings.ToLower(strings.TrimSpace(a.Confirm)) != st.Hostname {
		return nil, problemf("type the NetBird server's name (%s) to change this server's public address", st.Hostname)
	}
	if v4 != "" {
		v4 = netip.MustParseAddr(v4).String()
	}
	if v6 != "" {
		v6 = netip.MustParseAddr(v6).String()
	}
	st.PublicIPv4, st.PublicIPv6 = v4, v6
	if err := r.save(st); err != nil {
		return nil, err
	}
	return st.status(), nil
}

// Script is the VPS script for root's own key, name and from= addresses.
func (r *Root) Script(ctx context.Context) (*ScriptResult, error) {
	r.mu.Lock()
	st, err := r.load()
	r.mu.Unlock()
	if err != nil {
		return nil, err
	}
	sc, err := Script(ScriptSetup{Hostname: st.Hostname, PublicKey: st.PublicKey, From: st.From})
	if err != nil {
		return nil, &Problem{Msg: err.Error()}
	}
	return &ScriptResult{Script: sc, Fingerprint: KeyFingerprint(st.PublicKey)}, nil
}

// KeyFingerprint is an authorized_keys line's SHA-256 fingerprint ("" if
// it isn't one).
func KeyFingerprint(line string) string {
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return ""
	}
	return Fingerprint(pk)
}

// Fence stops the VPS's NetBird server (take-over); Unfence starts it again
// (hand-back without sending state).
func (r *Root) Fence(ctx context.Context, on bool) error {
	// Never at the same time as a hand-back: a renewal must not stop the
	// server the VPS just started with the handed-back state.
	r.syncMu.Lock()
	defer r.syncMu.Unlock()
	r.mu.Lock()
	st, err := r.load()
	if err == nil && on && st.Mode == ModeTakenOver && st.Returned {
		err = problemf("the VPS runs NetBird again for this hand-back: not fenced")
	}
	if err == nil && !on && st.Mode == ModeTakenOver && !st.Returned {
		st.Returned = true
		err = r.save(st)
	}
	if err == nil && on && st.Mode != ModeTakenOver {
		// Not a renewal: at most MaxFences a day.
		var recent []time.Time
		for _, t := range st.Fences {
			if r.now().Sub(t) < 24*time.Hour {
				recent = append(recent, t)
			}
		}
		if len(recent) >= MaxFences {
			err = problemf("the VPS was fenced %d times in 24 hours without a take-over: refused (start or stop netbird-server on the VPS by hand if you need to)", len(recent))
		} else {
			st.Fences = append(recent, r.now())
			err = r.save(st)
		}
	}
	r.mu.Unlock()
	if err != nil {
		return err
	}
	if on {
		r.log().Warn("netbird standby: fencing the VPS (its netbird-server stops)", "vps", st.VPSHost, "renewal", st.Mode == ModeTakenOver)
	} else {
		r.log().Warn("netbird standby: unfencing the VPS", "vps", st.VPSHost)
	}
	remote, err := r.target(st)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	verb := VerbFence
	if !on {
		verb = VerbUnfence
	}
	var out limitedBuffer
	out.n = 1 << 10
	return remote.Run(ctx, verb, nil, &out)
}

func (r *Root) target(st *state) (Remote, error) {
	if st.VPSHost == "" || len(st.KeySealed) == 0 || st.HostKey == "" || st.Hostname == "" {
		return nil, problemf("set up the VPS connection first")
	}
	hk, err := ParseHostKey(st.HostKey)
	if err != nil {
		return nil, err
	}
	k, err := r.Key()
	if err != nil {
		return nil, err
	}
	seed, err := gcmOpen(k, st.KeySealed, keyAAD())
	if err != nil {
		return nil, problemf("the SSH key can't be opened with this server's key: make a new one")
	}
	signer, err := SignerFromSeed(seed)
	if err != nil {
		return nil, err
	}
	t := SSHTarget{Host: st.VPSHost, Port: st.VPSPort, User: st.VPSUser, HostKey: hk, Signer: signer}
	if r.Remote != nil {
		return r.Remote(t), nil
	}
	return t, nil
}

func (r *Root) snapPath(id string) string { return filepath.Join(r.Dir, "snap-"+id+".sealed") }

func (r *Root) dropSnapshots(st *state, keep map[string]bool) {
	var kept []SnapshotRecord
	for _, s := range st.Snapshots {
		if keep[s.ID] {
			kept = append(kept, s)
			continue
		}
		if err := os.Remove(r.snapPath(s.ID)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			r.log().Warn("removing an old NetBird snapshot", "id", s.ID, "err", err)
		}
	}
	st.Snapshots = kept
}

var snapIDTime = "20060102T150405.000000000Z"

// Sync pulls one snapshot from the VPS, checks it and keeps it sealed.
// Refused while taken over (the VPS's copy is older than the standby's).
func (r *Root) Sync(ctx context.Context) (*SnapshotRecord, error) {
	r.syncMu.Lock()
	defer r.syncMu.Unlock()
	r.mu.Lock()
	st, err := r.load()
	r.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if st.Mode == ModeTakenOver {
		return nil, problemf("HardyOS has taken over: there is nothing to sync until hand-back")
	}
	rec, syncErr := r.pull(ctx, st)
	r.mu.Lock()
	defer r.mu.Unlock()
	cur, err := r.load()
	if err != nil {
		return nil, err
	}
	cur.LastTry = r.now()
	if syncErr != nil {
		cur.LastError = clip(syncErr.Error(), 300)
	} else if cur.Hostname != st.Hostname || cur.Mode != ModeStandby {
		// Reconfigured or taken over meanwhile: this copy isn't wanted.
		_ = os.Remove(r.snapPath(rec.ID))
		syncErr = problemf("the standby's settings changed during the sync")
		cur.LastError = syncErr.Error()
	} else {
		cur.LastOK, cur.LastError = cur.LastTry, ""
		if cur.Handback != "" {
			// The VPS has a good copy again: the hand-back copy can go.
			_ = os.Remove(filepath.Join(r.Dir, cur.Handback))
			cur.Handback = ""
		}
		cur.Snapshots = append(cur.Snapshots, *rec)
		sort.Slice(cur.Snapshots, func(i, j int) bool { return cur.Snapshots[i].At.After(cur.Snapshots[j].At) })
		keep := map[string]bool{}
		for i, s := range cur.Snapshots {
			if i < KeepSnapshots {
				keep[s.ID] = true
			}
		}
		r.dropSnapshots(cur, keep)
	}
	if err := r.save(cur); err != nil {
		return nil, err
	}
	if syncErr != nil {
		return nil, syncErr
	}
	return rec, nil
}

func (r *Root) pull(ctx context.Context, st *state) (*SnapshotRecord, error) {
	remote, err := r.target(st)
	if err != nil {
		return nil, err
	}
	key, err := r.Key()
	if err != nil {
		return nil, err
	}
	dir, err := os.OpenRoot(r.Dir)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	var rnd [4]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return nil, err
	}
	id := strings.ReplaceAll(r.now().Format(snapIDTime), ".", "") + "-" + hex.EncodeToString(rnd[:])
	tmpName := ".incoming-" + id
	f, err := dir.OpenFile(tmpName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			_ = dir.Remove(tmpName)
		}
	}()
	counted := &countWriter{w: f}
	sw, err := NewSealWriter(counted, key)
	if err != nil {
		return nil, err
	}
	pr, pw := io.Pipe()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	runErr := make(chan error, 1)
	go func() {
		err := remote.Run(ctx, VerbSnapshot, nil, pw)
		pw.CloseWithError(err)
		runErr <- err
	}()
	info, checkErr := Check(io.TeeReader(pr, sw), st.Hostname, nil)
	if checkErr != nil {
		pr.CloseWithError(checkErr)
		cancel()
	}
	rerr := <-runErr
	if rerr != nil && checkErr == nil {
		return nil, rerr
	}
	if checkErr != nil {
		if rerr != nil && !errors.Is(rerr, io.ErrClosedPipe) && !errors.Is(rerr, context.Canceled) && !strings.Contains(checkErr.Error(), "larger than") {
			// The VPS failed first (its message says why).
			var ve *VPSError
			if errors.As(rerr, &ve) {
				return nil, rerr
			}
		}
		return nil, checkErr
	}
	if err := sw.Close(); err != nil {
		return nil, err
	}
	if err := f.Sync(); err != nil {
		return nil, err
	}
	if err := dir.Rename(tmpName, "snap-"+id+".sealed"); err != nil {
		return nil, err
	}
	ok = true
	r.log().Info("netbird standby: snapshot pulled", "id", id, "bytes", info.Bytes)
	return &SnapshotRecord{ID: id, At: r.now(), Sealed: counted.n, Info: *info}, nil
}

type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// VPS asks the VPS how its NetBird server is.
func (r *Root) VPS(ctx context.Context) (*VPSStatus, error) {
	r.mu.Lock()
	st, err := r.load()
	r.mu.Unlock()
	if err != nil {
		return nil, err
	}
	remote, err := r.target(st)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	var out limitedBuffer
	out.n = 4 << 10
	if err := remote.Run(ctx, VerbStatus, nil, &out); err != nil {
		return nil, err
	}
	var vs VPSStatus
	if err := json.Unmarshal(bytes.TrimSpace(out.b.Bytes()), &vs); err != nil {
		return nil, errors.New("the VPS's status answer isn't what HardyOS's script prints (run the script again?)")
	}
	vs.Version, vs.Digest, vs.Image, vs.Hostname, vs.Time = clip(vs.Version, 40), clip(vs.Digest, 80), clip(vs.Image, 200), clip(vs.Hostname, 80), clip(vs.Time, 40)
	return &vs, nil
}

// ---- take-over -------------------------------------------------------------------

func (r *Root) app(ctx context.Context, wantStopped bool) (*os.Root, error) {
	if r.Apps == nil {
		return nil, ErrNoApp
	}
	dir, running, catalog, err := r.Apps.StandbyApp(ctx)
	if err != nil {
		return nil, err
	}
	if !catalog {
		// Only the package HardyOS ships gets the VPS's secrets.
		return nil, problemf("the installed netbird-standby app isn't HardyOS's own package: remove it and install the standby from Control Panel › NetBird Standby")
	}
	if wantStopped && running {
		return nil, problemf("the NetBird Standby app is running: stop it first")
	}
	return os.OpenRoot(dir)
}

// Where staged entries go in the app's data folder.
var stageTargets = map[string]string{
	EntryStore:  "data/store.db",
	EntryIDP:    "data/idp.db",
	EntryEvents: "data/events.db",
	EntryACME:   "letsencrypt/acme.json",
}

var stagedFiles = []string{"data/store.db", "data/idp.db", "data/events.db", "config/config.yaml", "letsencrypt/acme.json", "traefik/dynamic.yaml"}

type stageSink struct {
	root *os.Root
	cur  *os.File
	tmps map[string]string // target -> temporary name
}

func (s *stageSink) Begin(name string, _ int64) (io.Writer, error) {
	target, ok := stageTargets[name]
	if !ok {
		return nil, nil
	}
	if err := s.root.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return nil, err
	}
	tmp := filepath.Join(filepath.Dir(target), "."+filepath.Base(target)+".hardyos-new")
	_ = s.root.Remove(tmp)
	f, err := s.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	s.cur = f
	s.tmps[target] = tmp
	return f, nil
}

func (s *stageSink) End(string) error {
	if s.cur == nil {
		return nil
	}
	f := s.cur
	s.cur = nil
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func (s *stageSink) abort() {
	if s.cur != nil {
		s.cur.Close()
	}
	for _, t := range s.tmps {
		_ = s.root.Remove(t)
	}
}

// Stage writes the newest snapshot into the stopped app's data folder and
// marks the standby as taken over (decision 425). confirm is the hostname.
func (r *Root) Stage(ctx context.Context, a ConfirmArgs) (*StageResult, error) {
	r.syncMu.Lock()
	defer r.syncMu.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	st, err := r.load()
	if err != nil {
		return nil, err
	}
	if st.Hostname == "" || strings.ToLower(strings.TrimSpace(a.Confirm)) != st.Hostname {
		return nil, problemf("type the NetBird server's name (%s) to take over", st.Hostname)
	}
	if st.Mode == ModeTakenOver {
		return nil, problemf("HardyOS has already taken over")
	}
	if r.DNSBound != nil {
		bound, ok := r.DNSBound()
		if !ok {
			return nil, problemf("let HardyOS manage %s in Cloudflare first", st.Hostname)
		}
		if bound != st.binding() {
			return nil, problemf("the public address or the VPS changed since %s was allowed in Cloudflare: confirm again with the Cloudflare token (or hardyctl netbird-standby rebind on the console)", st.Hostname)
		}
	}
	if len(st.Snapshots) == 0 {
		return nil, problemf("there is no copy of the VPS's NetBird server yet: sync first")
	}
	snap := st.Snapshots[0]
	root, err := r.app(ctx, true)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	key, err := r.Key()
	if err != nil {
		return nil, err
	}
	f, err := os.Open(r.snapPath(snap.ID))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	plain, err := OpenReader(f, key)
	if err != nil {
		return nil, err
	}
	sink := &stageSink{root: root, tmps: map[string]string{}}
	c, err := check(plain, st.Hostname, sink)
	if err != nil {
		sink.abort()
		return nil, fmt.Errorf("the saved copy failed its checks: %w", err)
	}
	cfg, err := FoldSecrets(c.config, c.env)
	if err != nil {
		sink.abort()
		return nil, err
	}
	routes := TraefikRoutes(st.Hostname, listenPort(cfg))
	if tmp, ok := sink.tmps["letsencrypt/acme.json"]; ok {
		// Only the hostname's own certificate, without the ACME account's
		// key (Traefik registers a fresh account when it renews).
		// An empty or unreadable certificate store is skipped, not fatal:
		// Traefik gets a certificate of its own (review L-c).
		keep, err := filterACMEFile(root, tmp, st.Hostname)
		if err != nil {
			sink.abort()
			return nil, err
		}
		if !keep {
			r.log().Warn("netbird standby: the snapshot's acme.json is empty or unreadable; staged without the certificate")
			delete(sink.tmps, "letsencrypt/acme.json")
		}
	}
	// Everything checked: replace what the app has. Any failure from here
	// removes whatever was already put in place.
	fail := func(err error) (*StageResult, error) {
		sink.abort()
		removeStaged(root)
		return nil, err
	}
	for _, base := range []string{"data/store.db", "data/idp.db", "data/events.db"} {
		for _, sfx := range []string{"", "-wal", "-shm", "-journal"} {
			if err := root.Remove(base + sfx); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return fail(err)
			}
		}
	}
	for target, tmp := range sink.tmps {
		if err := root.Rename(tmp, target); err != nil {
			return fail(err)
		}
	}
	if err := writeIn(root, "config/config.yaml", cfg); err != nil {
		return fail(err)
	}
	if err := writeIn(root, "traefik/dynamic.yaml", []byte(routes)); err != nil {
		return fail(err)
	}
	st.Mode, st.Staged, st.TakenOver, st.Returned = ModeTakenOver, snap.ID, r.now(), false
	if err := r.save(st); err != nil {
		return fail(err)
	}
	r.log().Info("netbird standby: staged for take-over", "snapshot", snap.ID)
	return &StageResult{Snapshot: snap}, nil
}

func writeIn(root *os.Root, name string, b []byte) error {
	if err := root.MkdirAll(filepath.Dir(name), 0o700); err != nil {
		return err
	}
	tmp := filepath.Join(filepath.Dir(name), "."+filepath.Base(name)+".hardyos-new")
	_ = root.Remove(tmp)
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return root.Rename(tmp, name)
}

func listenPort(cfg []byte) int {
	v, _ := configValue(cfg, "server.listenAddress")
	if i := strings.LastIndex(v, ":"); i >= 0 {
		if p, err := strconv.Atoi(v[i+1:]); err == nil && p > 0 && p < 65536 {
			return p
		}
	}
	return 80
}

// TraefikRoutes are the standby Traefik's routes for host: the same as
// NetBird's quickstart labels (gRPC over h2c, relay, API and IdP to the
// server, everything else to the dashboard).
func TraefikRoutes(host string, port int) string {
	h := "Host(`" + host + "`)"
	return fmt.Sprintf(`# Written by HardyOS for the NetBird standby (decision 425). Do not edit.
http:
  routers:
    netbird-grpc:
      rule: "%[1]s && (PathPrefix(`+"`/signalexchange.SignalExchange/`"+`) || PathPrefix(`+"`/management.ManagementService/`"+`) || PathPrefix(`+"`/management.ProxyService/`"+`))"
      entryPoints: [websecure]
      service: netbird-server-h2c
      priority: 100
      tls:
        certResolver: letsencrypt
    netbird-backend:
      rule: "%[1]s && (PathPrefix(`+"`/relay`"+`) || PathPrefix(`+"`/ws-proxy/`"+`) || PathPrefix(`+"`/api`"+`) || PathPrefix(`+"`/oauth2`"+`))"
      entryPoints: [websecure]
      service: netbird-server
      priority: 100
      tls:
        certResolver: letsencrypt
    netbird-dashboard:
      rule: "%[1]s"
      entryPoints: [websecure]
      service: dashboard
      priority: 1
      tls:
        certResolver: letsencrypt
  services:
    netbird-server:
      loadBalancer:
        servers:
          - url: "http://netbird-server:%[2]d"
    netbird-server-h2c:
      loadBalancer:
        servers:
          - url: "h2c://netbird-server:%[2]d"
    dashboard:
      loadBalancer:
        servers:
          - url: "http://dashboard:80"
`, h, port)
}

// Network opens (only while taken over) or closes the standby's ports and
// HardyOS's own route to it.
func (r *Root) Network(ctx context.Context, a NetworkArgs) (*Status, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	st, err := r.load()
	if err != nil {
		return nil, err
	}
	if a.Open && st.Mode != ModeTakenOver {
		return nil, problemf("the standby's ports open only while HardyOS has taken over")
	}
	if r.Net == nil {
		return nil, errors.New("the firewall isn't available")
	}
	if err := r.Net.Apply(ctx, a.Open, st.Hostname); err != nil {
		return nil, err
	}
	st.NetOpen = a.Open
	if err := r.save(st); err != nil {
		return nil, err
	}
	return st.status(), nil
}

// Unstage removes the take-over's files from the stopped app and goes back
// to syncing (after hand-back, or to abandon a take-over that never changed
// DNS). confirm is the hostname.
func (r *Root) Unstage(ctx context.Context, a ConfirmArgs) (*Status, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	st, err := r.load()
	if err != nil {
		return nil, err
	}
	if st.Hostname == "" || strings.ToLower(strings.TrimSpace(a.Confirm)) != st.Hostname {
		return nil, problemf("type the NetBird server's name (%s)", st.Hostname)
	}
	if st.Mode != ModeTakenOver {
		return st.status(), nil
	}
	root, err := r.app(ctx, true)
	if err != nil && !errors.Is(err, ErrNoApp) {
		return nil, err
	}
	if root != nil {
		defer root.Close()
		if err := removeStaged(root); err != nil {
			return nil, err
		}
	}
	if r.Net != nil {
		if err := r.Net.Apply(ctx, false, st.Hostname); err != nil {
			return nil, err
		}
	}
	st.Mode, st.Staged, st.TakenOver, st.NetOpen, st.Returned = ModeStandby, "", time.Time{}, false, false
	if err := r.save(st); err != nil {
		return nil, err
	}
	return st.status(), nil
}

// removeStaged removes a take-over's files from the app's data folder.
func removeStaged(root *os.Root) error {
	var first error
	for _, f := range stagedFiles {
		for _, sfx := range []string{"", "-wal", "-shm", "-journal"} {
			if sfx != "" && !strings.HasSuffix(f, ".db") {
				continue
			}
			if err := root.Remove(f + sfx); err != nil && !errors.Is(err, fs.ErrNotExist) && first == nil {
				first = err
			}
		}
	}
	return first
}

// filterACMEFile keeps only host's certificate in name; false (and name
// removed) when the store is empty or isn't Traefik's.
func filterACMEFile(root *os.Root, name, host string) (bool, error) {
	f, err := root.Open(name)
	if err != nil {
		return false, err
	}
	b, err := io.ReadAll(io.LimitReader(f, entryLimits[EntryACME]+1))
	f.Close()
	if err != nil {
		return false, err
	}
	out, ferr := FilterACME(b, host)
	if err := root.Remove(name); err != nil {
		return false, err
	}
	if ferr != nil || len(bytes.TrimSpace(b)) == 0 {
		return false, nil
	}
	w, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return false, err
	}
	if _, err := w.Write(out); err != nil {
		w.Close()
		return false, err
	}
	if err := w.Sync(); err != nil {
		w.Close()
		return false, err
	}
	return true, w.Close()
}

// Handback sends the stopped standby's databases to the VPS (restore verb),
// which backs its own up first. confirm is the hostname.
func (r *Root) Handback(ctx context.Context, a ConfirmArgs) (*HandbackResult, error) {
	r.syncMu.Lock()
	defer r.syncMu.Unlock()
	r.mu.Lock()
	st, err := r.load()
	r.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if st.Hostname == "" || strings.ToLower(strings.TrimSpace(a.Confirm)) != st.Hostname {
		return nil, problemf("type the NetBird server's name (%s) to hand back", st.Hostname)
	}
	if st.Mode != ModeTakenOver {
		return nil, problemf("HardyOS hasn't taken over")
	}
	root, err := r.app(ctx, true)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	remote, err := r.target(st)
	if err != nil {
		return nil, err
	}
	gen := ""
	for _, sn := range st.Snapshots {
		if sn.ID == st.Staged {
			gen = sn.Info.Generation
		}
	}
	if !generationRE.MatchString(gen) {
		return nil, problemf("the copy the standby started from has no generation id (made by an older VPS script): run the VPS script again, then hand back")
	}
	sums, err := restoreSums(root)
	if err != nil {
		return nil, err
	}
	// A sealed copy of exactly what goes to the VPS stays here until the
	// next good sync, in case the VPS loses it.
	key, err := r.Key()
	if err != nil {
		return nil, err
	}
	copyName := "handback-" + strings.ReplaceAll(r.now().Format(snapIDTime), ".", "") + ".sealed"
	cf, err := os.OpenFile(filepath.Join(r.Dir, copyName), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		cf.Close()
		if !keep {
			_ = os.Remove(filepath.Join(r.Dir, copyName))
		}
	}()
	sealed, err := NewSealWriter(cf, key)
	if err != nil {
		return nil, err
	}
	pr, pw := io.Pipe()
	counted := &countWriter{w: io.MultiWriter(pw, sealed)}
	go func() {
		pw.CloseWithError(writeRestoreTar(counted, root, sums, map[string]string{"GENERATION": gen + "\n", "VERSION": StandbyVersion + "\n"}))
	}()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	var out limitedBuffer
	out.n = 8 << 10
	err = remote.Run(ctx, VerbRestore, pr, &out)
	pr.Close()
	if err != nil {
		return nil, err
	}
	if err := sealed.Close(); err != nil {
		return nil, err
	}
	if err := cf.Sync(); err != nil {
		return nil, err
	}
	r.mu.Lock()
	if cur, err := r.load(); err == nil {
		if cur.Handback != "" && cur.Handback != copyName {
			_ = os.Remove(filepath.Join(r.Dir, cur.Handback))
		}
		cur.Handback = copyName
		cur.Returned = true
		if r.save(cur) == nil {
			keep = true
		}
	}
	r.mu.Unlock()
	r.log().Info("netbird standby: handed back", "bytes", counted.n)
	return &HandbackResult{Message: clip(strings.TrimSpace(out.b.String()), 1500), Bytes: counted.n}, nil
}

// restoreFiles are what hand-back sends, when present.
var restoreFiles = []string{"data/store.db", "data/store.db-wal", "data/idp.db", "data/idp.db-wal", "data/events.db", "data/events.db-wal"}

func restoreSums(root *os.Root) (map[string]string, error) {
	sums := map[string]string{}
	for _, name := range restoreFiles {
		f, err := root.Open(name)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		fi, err := f.Stat()
		if err != nil || !fi.Mode().IsRegular() {
			f.Close()
			return nil, fmt.Errorf("%s isn't a regular file", name)
		}
		h := sha256.New()
		_, err = io.Copy(h, f)
		f.Close()
		if err != nil {
			return nil, err
		}
		sums[name] = hex.EncodeToString(h.Sum(nil))
	}
	if sums["data/store.db"] == "" {
		return nil, problemf("the standby has no store.db to hand back")
	}
	return sums, nil
}

func writeRestoreTar(w io.Writer, root *os.Root, sums map[string]string, extra map[string]string) error {
	tw := tar.NewWriter(w)
	var extraNames []string
	for n := range extra {
		extraNames = append(extraNames, n)
	}
	sort.Strings(extraNames)
	for _, n := range extraNames {
		if err := tw.WriteHeader(&tar.Header{Name: n, Mode: 0o600, Size: int64(len(extra[n])), Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		if _, err := io.WriteString(tw, extra[n]); err != nil {
			return err
		}
	}
	var names []string
	for n := range sums {
		names = append(names, n)
	}
	sort.Strings(names)
	var list strings.Builder
	for _, n := range names {
		fmt.Fprintf(&list, "%s  %s\n", sums[n], n)
	}
	if err := tw.WriteHeader(&tar.Header{Name: "SHA256SUMS", Mode: 0o600, Size: int64(list.Len()), Typeflag: tar.TypeReg}); err != nil {
		return err
	}
	if _, err := io.WriteString(tw, list.String()); err != nil {
		return err
	}
	for _, n := range names {
		f, err := root.Open(n)
		if err != nil {
			return err
		}
		fi, err := f.Stat()
		if err != nil {
			f.Close()
			return err
		}
		h := sha256.New()
		if err := tw.WriteHeader(&tar.Header{Name: n, Mode: 0o600, Size: fi.Size(), Typeflag: tar.TypeReg}); err != nil {
			f.Close()
			return err
		}
		_, err = io.Copy(io.MultiWriter(tw, h), io.LimitReader(f, fi.Size()))
		f.Close()
		if err != nil {
			return err
		}
		if hex.EncodeToString(h.Sum(nil)) != sums[n] {
			return fmt.Errorf("%s changed while it was sent (is the standby stopped?)", n)
		}
	}
	return tw.Close()
}

// Forget removes the connection, the key and every snapshot (not while
// taken over). confirm is the hostname (anything when none is set).
func (r *Root) Forget(ctx context.Context, a ConfirmArgs) (*Status, error) {
	r.syncMu.Lock()
	defer r.syncMu.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	st, err := r.load()
	if err != nil {
		return nil, err
	}
	if st.Mode == ModeTakenOver {
		return nil, problemf("HardyOS has taken over: hand back first")
	}
	if st.Hostname != "" && strings.ToLower(strings.TrimSpace(a.Confirm)) != st.Hostname {
		return nil, problemf("type the NetBird server's name (%s) to forget the standby", st.Hostname)
	}
	r.dropSnapshots(st, nil)
	empty := &state{V: 1, Mode: ModeStandby}
	if err := r.save(empty); err != nil {
		return nil, err
	}
	r.applyNet(ctx, empty)
	return empty.status(), nil
}

// applyNet puts the firewall table in the state's shape: open while taken
// over (and opened), closed while the app is installed or a connection is
// set up, gone otherwise.
func (r *Root) applyNet(ctx context.Context, st *state) {
	if r.Net == nil {
		return
	}
	installed := false
	if r.Apps != nil {
		_, _, _, err := r.Apps.StandbyApp(ctx)
		installed = err == nil
	}
	var err error
	switch {
	case st.Mode == ModeTakenOver && st.NetOpen:
		err = r.Net.Apply(ctx, true, st.Hostname)
	case installed || st.VPSHost != "":
		err = r.Net.Apply(ctx, false, st.Hostname)
	default:
		err = r.Net.Remove(ctx)
	}
	if err != nil {
		r.log().Warn("netbird standby: firewall", "err", err)
	}
}

// OnStart puts the firewall back after hardyd-priv starts (nft tables don't
// survive a restart), and removes leftovers of a sync that was cut off.
func (r *Root) OnStart(ctx context.Context) {
	r.mu.Lock()
	st, err := r.load()
	r.mu.Unlock()
	if err != nil {
		r.log().Warn("netbird standby: state", "err", err)
		return
	}
	if entries, err := os.ReadDir(r.Dir); err == nil {
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), ".incoming-") {
				_ = os.Remove(filepath.Join(r.Dir, e.Name()))
			}
		}
	}
	r.applyNet(ctx, st)
}

// TakeOverInfo is what root's DNS operations need from the standby's state:
// the binding (decision 424) of name, this server's addresses and the VPS.
type TakeOverInfo = Binding

// Binding is what the administrator allowed when adopting the NetBird name
// with the Cloudflare token (decision 424): the name, the addresses DNS may
// point it at, and the VPS (address, port, host key) copies come from. If
// any of them changes afterwards, a take-over refuses until the token is
// pasted again (or `hardyctl netbird-standby rebind` runs on the console).
type Binding struct {
	Host      string `json:"host"`
	IPv4      string `json:"ipv4"`
	IPv6      string `json:"ipv6"`
	VPSHost   string `json:"vpsHost"`
	VPSPort   int    `json:"vpsPort"`
	HostKeyFP string `json:"hostKeyFingerprint"`
}

func (st *state) binding() Binding {
	b := Binding{Host: st.Hostname, IPv4: st.PublicIPv4, IPv6: st.PublicIPv6, VPSHost: st.VPSHost, VPSPort: st.VPSPort}
	if pk, err := ParseHostKey(st.HostKey); err == nil {
		b.HostKeyFP = Fingerprint(pk)
	}
	return b
}

// CurrentBinding reads root's state in dir (false when the standby isn't
// configured).
func CurrentBinding(dir string) (Binding, bool) {
	r := &Root{Dir: dir}
	r.mu.Lock()
	defer r.mu.Unlock()
	st, err := r.load()
	if err != nil || st.Hostname == "" || st.VPSHost == "" {
		return Binding{}, false
	}
	return st.binding(), true
}

// SetAddressConsole sets the public addresses from the console (hardyctl,
// as root), with the same checks as Address but no typed name: the person
// at the console is the confirmation. A bound adoption must be confirmed
// again (rebind) afterwards.
func SetAddressConsole(dir, ipv4, ipv6 string) (*Status, error) {
	r := &Root{Dir: dir}
	st, err := r.Status(context.Background())
	if err != nil {
		return nil, err
	}
	return r.Address(context.Background(), AddressArgs{IPv4: ipv4, IPv6: ipv6, Confirm: st.Hostname})
}

// TakenOver reads root's state in dir and, when the standby has taken
// over, returns its hostname and the public addresses set in root: the
// standby name may point here, at exactly those, only then.
func TakenOver(dir string) (TakeOverInfo, bool) {
	r := &Root{Dir: dir}
	r.mu.Lock()
	defer r.mu.Unlock()
	st, err := r.load()
	if err != nil || st.Mode != ModeTakenOver || st.Hostname == "" {
		return TakeOverInfo{}, false
	}
	return st.binding(), true
}

// SyncApp re-applies the firewall after the app was installed or removed.
func (r *Root) SyncApp(ctx context.Context) {
	r.mu.Lock()
	st, err := r.load()
	r.mu.Unlock()
	if err == nil {
		r.applyNet(ctx, st)
	}
}
