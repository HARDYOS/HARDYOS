package nbstandby

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/store"
)

// hardyd's side (decisions 423, 425, 427, 428): the schedule and alerts,
// the sync history, and take-over and hand-back as ordered steps over root
// operations (Backend), each undone in reverse when a later one fails before
// anything outside this server changed.

// StandbyVersion is the netbird-server version the app pins
// (apps/catalog/netbird-standby).
const StandbyVersion = "0.83.1"

// Settings keys.
const (
	settingSettings = "nbstandby.settings"
	settingAlerts   = "nbstandby.alerts"
	settingTakeover = "nbstandby.takeover"
)

// Settings are hardyd's part of the configuration.
type Settings struct {
	// IntervalMinutes between syncs (5-1440, default 15).
	IntervalMinutes int  `json:"intervalMinutes"`
	AutoSync        bool `json:"autoSync"`
	// PublicIPv4/IPv6: where the router forwards the NetBird ports; DNS
	// points the name here on a take-over.
	PublicIPv4 string `json:"publicIPv4"`
	PublicIPv6 string `json:"publicIPv6"`
	// ConnectFrom are the addresses HardyOS reaches the VPS from (the
	// script's from= restriction); empty means none.
	ConnectFrom []string `json:"connectFrom"`
}

// DefaultSettings are used before anything is saved.
func DefaultSettings() Settings {
	return Settings{IntervalMinutes: 15, AutoSync: true, ConnectFrom: []string{}}
}

// PublicAddr reports whether s is an internet address of family v4 (or v6).
func PublicAddr(s string, v4 bool) bool {
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" || a.Is4In6() || a.Is4() != v4 {
		return false
	}
	if !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLinkLocalUnicast() {
		return false
	}
	return !netip.MustParsePrefix("100.64.0.0/10").Contains(a)
}

// Validate checks settings.
func (s *Settings) Validate() error {
	if s.IntervalMinutes == 0 {
		s.IntervalMinutes = 15
	}
	if s.IntervalMinutes < 5 || s.IntervalMinutes > 1440 {
		return errors.New("sync every 5 to 1440 minutes")
	}
	s.PublicIPv4, s.PublicIPv6 = strings.TrimSpace(s.PublicIPv4), strings.TrimSpace(s.PublicIPv6)
	if s.PublicIPv4 != "" && !PublicAddr(s.PublicIPv4, true) {
		return fmt.Errorf("%q isn't a public IPv4 address", clip(s.PublicIPv4, 60))
	}
	if s.PublicIPv6 != "" && !PublicAddr(s.PublicIPv6, false) {
		return fmt.Errorf("%q isn't a public IPv6 address", clip(s.PublicIPv6, 60))
	}
	if s.ConnectFrom == nil {
		s.ConnectFrom = []string{}
	}
	return ScriptSetup{Hostname: "x.invalid", From: s.ConnectFrom}.validateFrom()
}

func (s ScriptSetup) validateFrom() error {
	if len(s.From) > 8 {
		return errors.New("at most 8 addresses HardyOS connects from")
	}
	for _, f := range s.From {
		if _, err := netip.ParsePrefix(f); err == nil {
			continue
		}
		if _, err := netip.ParseAddr(f); err != nil {
			return fmt.Errorf("%q isn't an address or prefix", clip(f, 60))
		}
	}
	return nil
}

// SyncRow is one sync attempt.
type SyncRow struct {
	StartedAt  time.Time `json:"startedAt"`
	FinishedAt time.Time `json:"finishedAt"`
	OK         bool      `json:"ok"`
	Auto       bool      `json:"auto"`
	Bytes      int64     `json:"bytes"`
	SHA256     string    `json:"sha256"`
	Version    string    `json:"version"`
	Peers      int       `json:"peers"`
	Error      string    `json:"error"`
}

// TakeoverRecord is what Control Panel shows about the current take-over.
type TakeoverRecord struct {
	At         time.Time `json:"at"`
	By         string    `json:"by"`
	SnapshotAt time.Time `json:"snapshotAt"`
	// FinalSync: a last copy was pulled right before (else the VPS didn't
	// answer and the newest saved one was used).
	FinalSync      bool      `json:"finalSync"`
	FinalSyncError string    `json:"finalSyncError,omitempty"`
	DNSChanged     bool      `json:"dnsChanged"`
	IPv4           string    `json:"ipv4"`
	IPv6           string    `json:"ipv6,omitempty"`
	PeersTotal     int       `json:"peersTotal"`
	PeersConnected int       `json:"peersConnected"`
	PeersCheckedAt time.Time `json:"peersCheckedAt,omitzero"`
	PeersProblem   string    `json:"peersProblem,omitempty"`
	Notes          []string  `json:"notes"`
}

// Service is hardyd's side.
type Service struct {
	DB *store.DB
	// Notify raises an administrator alert (level info, warning, error).
	Notify func(ctx context.Context, level, title, body string)
	Now    func() time.Time
	// PeerWait is how long a take-over watches peers reconnect (default
	// 3 minutes); PeerPoll how often (default 10 s).
	PeerWait, PeerPoll time.Duration
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// Settings loads the settings.
func (s *Service) Settings(ctx context.Context) (Settings, error) {
	out := DefaultSettings()
	v, err := s.setting(ctx, settingSettings)
	if err != nil || v == "" {
		return out, err
	}
	if err := json.Unmarshal([]byte(v), &out); err != nil {
		return DefaultSettings(), nil
	}
	if out.ConnectFrom == nil {
		out.ConnectFrom = []string{}
	}
	return out, nil
}

// setting reads a settings row ("" when there is none).
func (s *Service) setting(ctx context.Context, key string) (string, error) {
	v, err := s.DB.GetSetting(ctx, key)
	if errors.Is(err, store.ErrNotFound) {
		return "", nil
	}
	return v, err
}

// SaveSettings validates and saves.
func (s *Service) SaveSettings(ctx context.Context, set Settings) (Settings, error) {
	if err := set.Validate(); err != nil {
		return set, err
	}
	b, _ := json.Marshal(set)
	return set, s.DB.SetSetting(ctx, settingSettings, string(b))
}

// RecordSync adds one attempt to the history (the newest 500 are kept).
func (s *Service) RecordSync(ctx context.Context, r SyncRow) error {
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO nbstandby_syncs (started_at, finished_at, ok, auto, bytes, sha256, version, peers, error)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, store.FormatTime(r.StartedAt), store.FormatTime(r.FinishedAt), boolInt(r.OK), boolInt(r.Auto),
		r.Bytes, r.SHA256, r.Version, r.Peers, clip(r.Error, 300)); err != nil {
		return err
	}
	_, err := s.DB.ExecContext(ctx, `DELETE FROM nbstandby_syncs WHERE id NOT IN (SELECT id FROM nbstandby_syncs ORDER BY id DESC LIMIT 500)`)
	return err
}

// History returns the newest n attempts, newest first.
func (s *Service) History(ctx context.Context, n int) ([]SyncRow, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT started_at, finished_at, ok, auto, bytes, sha256, version, peers, error
		FROM nbstandby_syncs ORDER BY id DESC LIMIT ?`, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SyncRow{}
	for rows.Next() {
		var r SyncRow
		var st, fin string
		var ok, auto int
		if err := rows.Scan(&st, &fin, &ok, &auto, &r.Bytes, &r.SHA256, &r.Version, &r.Peers, &r.Error); err != nil {
			return nil, err
		}
		r.StartedAt, r.FinishedAt, r.OK, r.Auto = store.ParseTime(st), store.ParseTime(fin), ok == 1, auto == 1
		out = append(out, r)
	}
	return out, rows.Err()
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// StaleAfter is how long without a good sync before it's stale:
// max(3 intervals, interval + 1 hour).
func StaleAfter(set Settings) time.Duration {
	iv := time.Duration(set.IntervalMinutes) * time.Minute
	return max(3*iv, iv+time.Hour)
}

// Health is the standby's state at a glance.
type Health struct {
	// State: unconfigured, waiting (configured, no copy yet), ok, failing
	// (the last attempt failed but a recent copy exists), stale, takenover.
	State      string    `json:"state"`
	Stale      bool      `json:"stale"`
	StaleAfter int       `json:"staleAfterMinutes"`
	NextSync   time.Time `json:"nextSync,omitzero"`
	Problem    string    `json:"problem,omitempty"`
}

// HealthOf works out the health.
func HealthOf(st *Status, set Settings, now time.Time) Health {
	h := Health{StaleAfter: int(StaleAfter(set) / time.Minute)}
	switch {
	case st == nil || !st.Configured:
		h.State = "unconfigured"
		return h
	case st.Mode == ModeTakenOver:
		h.State = "takenover"
		return h
	}
	if set.AutoSync {
		last := st.LastTry
		if last.IsZero() {
			h.NextSync = now
		} else {
			h.NextSync = last.Add(time.Duration(set.IntervalMinutes) * time.Minute)
		}
	}
	since := st.LastOK
	if since.IsZero() {
		since = st.KeyCreated
	}
	h.Stale = !since.IsZero() && now.Sub(since) > StaleAfter(set)
	switch {
	case h.Stale:
		h.State, h.Problem = "stale", st.LastError
	case st.LastOK.IsZero():
		h.State, h.Problem = "waiting", st.LastError
	case st.LastError != "" && st.LastTry.After(st.LastOK):
		h.State, h.Problem = "failing", st.LastError
	default:
		h.State = "ok"
	}
	return h
}

// Due reports whether an automatic sync should start now.
func Due(st *Status, set Settings, now time.Time) bool {
	if st == nil || !st.Configured || st.Mode != ModeStandby || !set.AutoSync {
		return false
	}
	return st.LastTry.IsZero() || now.Sub(st.LastTry) >= time.Duration(set.IntervalMinutes)*time.Minute
}

type alertState struct {
	Failed bool `json:"failed"`
	Stale  bool `json:"stale"`
}

// CheckAlerts raises a warning when a sync fails (once until one works), a
// critical alert when the copy goes stale (once), and an info when it
// recovers (decision 423).
func (s *Service) CheckAlerts(ctx context.Context, st *Status, set Settings) {
	if s.Notify == nil || st == nil {
		return
	}
	var a alertState
	if v, _ := s.setting(ctx, settingAlerts); v != "" {
		_ = json.Unmarshal([]byte(v), &a)
	}
	old := a
	h := HealthOf(st, set, s.now())
	failing := h.State == "failing" || h.State == "stale" || (h.State == "waiting" && st.LastError != "")
	switch {
	case h.State == "unconfigured" || h.State == "takenover":
		a = alertState{}
	default:
		if failing && !a.Failed {
			s.Notify(ctx, "warning", "The NetBird standby couldn't copy the VPS", st.LastError+" HardyOS tries again on schedule.")
			a.Failed = true
		}
		if h.Stale && !a.Stale {
			s.Notify(ctx, "error", "The NetBird standby's copy is out of date",
				fmt.Sprintf("No good copy of the VPS's NetBird server for over %d minutes. A take-over now would bring back older peers and settings. Last problem: %s", h.StaleAfter, orNone(st.LastError)))
			a.Stale = true
		}
		if !failing && !h.Stale && (a.Failed || a.Stale) {
			s.Notify(ctx, "info", "The NetBird standby is copying the VPS again", "The last copy worked.")
			a = alertState{}
		}
	}
	if a != old {
		b, _ := json.Marshal(a)
		_ = s.DB.SetSetting(ctx, settingAlerts, string(b))
	}
}

func orNone(s string) string {
	if s == "" {
		return "none recorded"
	}
	return s
}

// Takeover returns the current take-over's record (nil when none).
func (s *Service) Takeover(ctx context.Context) (*TakeoverRecord, error) {
	v, err := s.setting(ctx, settingTakeover)
	if err != nil || v == "" {
		return nil, err
	}
	var r TakeoverRecord
	if err := json.Unmarshal([]byte(v), &r); err != nil {
		return nil, nil
	}
	return &r, nil
}

func (s *Service) saveTakeover(ctx context.Context, r *TakeoverRecord) error {
	if r == nil {
		return s.DB.SetSetting(ctx, settingTakeover, "")
	}
	b, _ := json.Marshal(r)
	return s.DB.SetSetting(ctx, settingTakeover, string(b))
}

// CompareVersions compares dotted versions (a leading v ignored): -1, 0, 1;
// ok is false when either isn't a version.
func CompareVersions(a, b string) (int, bool) {
	pa, oka := versionParts(a)
	pb, okb := versionParts(b)
	if !oka || !okb {
		return 0, false
	}
	for i := 0; i < max(len(pa), len(pb)); i++ {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			if x < y {
				return -1, true
			}
			return 1, true
		}
	}
	return 0, true
}

func versionParts(v string) ([]int, bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if v == "" {
		return nil, false
	}
	var out []int
	for _, p := range strings.Split(v, ".") {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, false
		}
		out = append(out, n)
	}
	return out, true
}

// VersionNote says how the VPS's version compares with the standby's.
// newer is true when the VPS runs a newer server (its store may have been
// migrated past what the standby knows).
func VersionNote(vps string) (note string, newer bool) {
	c, ok := CompareVersions(vps, StandbyVersion)
	switch {
	case !ok:
		return "The VPS's NetBird version isn't known (" + orNone(clip(vps, 40)) + "); the standby runs " + StandbyVersion + ".", false
	case c > 0:
		return "The VPS runs NetBird " + vps + ", newer than the standby's " + StandbyVersion + ": update HardyOS before relying on the standby.", true
	case c < 0:
		return "The VPS runs NetBird " + vps + ", older than the standby's " + StandbyVersion + " (the standby migrates the copy forward on a take-over; hand-back then needs the VPS updated too).", false
	}
	return "", false
}

// ---- take-over and hand-back -------------------------------------------------------

// Backend is what the steps use: root operations and the app.
type Backend interface {
	Status(ctx context.Context) (*Status, error)
	Sync(ctx context.Context) (*SnapshotRecord, error)
	VPS(ctx context.Context) (*VPSStatus, error)
	Stage(ctx context.Context, confirm string) (*StageResult, error)
	Unstage(ctx context.Context, confirm string) error
	Network(ctx context.Context, open bool) error
	Handback(ctx context.Context, confirm string) (*HandbackResult, error)
	AppUp(ctx context.Context) error
	AppStop(ctx context.Context) error
	// DNSStandby is the adopted name and whether an AAAA was adopted.
	DNSStandby(ctx context.Context) (name string, hasAAAA bool, err error)
	DNSSet(ctx context.Context, typ, content string) error
	DNSRestore(ctx context.Context) error
	// Peers counts NetBird peers through the (now local) management API.
	Peers(ctx context.Context) (total, connected int, err error)
}

// ErrNoPeerCheck means peers can't be counted at all (no NetBird access
// token): the take-over doesn't wait for them.
var ErrNoPeerCheck = errors.New("peers can't be counted without Remote Access's NetBird access token")

// Progress reports a step.
type Progress func(pct float64, msg string)

// TakeOverArgs are the administrator's choices.
type TakeOverArgs struct {
	Confirm       string `json:"confirm"`
	AcceptVersion bool   `json:"acceptVersion"`
	SkipFinalSync bool   `json:"skipFinalSync"`
	By            string `json:"-"`
}

// ErrVersion means the VPS runs a newer NetBird than the standby.
var ErrVersion = errors.New("version")

// CheckTakeOver says why a take-over can't start (nil when it can).
func (s *Service) CheckTakeOver(st *Status, set Settings, dnsName string, hasAAAA bool, a TakeOverArgs) error {
	switch {
	case st == nil || !st.Configured:
		return &Problem{Msg: "set up the standby first"}
	case st.Mode == ModeTakenOver:
		return &Problem{Msg: "HardyOS has already taken over"}
	case strings.ToLower(strings.TrimSpace(a.Confirm)) != st.Hostname:
		return &Problem{Msg: "type the NetBird server's name (" + st.Hostname + ") to take over"}
	case len(st.Snapshots) == 0 && a.SkipFinalSync:
		return &Problem{Msg: "there is no copy of the VPS yet"}
	case !PublicAddr(set.PublicIPv4, true):
		return &Problem{Msg: "enter this server's public IPv4 address first (where the router forwards the NetBird ports)"}
	case dnsName != st.Hostname:
		return &Problem{Msg: "let HardyOS manage " + st.Hostname + "'s DNS records first (DNS step)"}
	case hasAAAA && set.PublicIPv6 == "":
		return &Problem{Msg: st.Hostname + " has an AAAA record: enter this server's public IPv6 address, or remove the AAAA record in Cloudflare and adopt the name again"}
	}
	if len(st.Snapshots) > 0 {
		if _, newer := VersionNote(st.Snapshots[0].Info.Version); newer && !a.AcceptVersion {
			return fmt.Errorf("%w: the VPS runs NetBird %s, newer than the standby's %s", ErrVersion, st.Snapshots[0].Info.Version, StandbyVersion)
		}
	}
	return nil
}

// TakeOver runs the take-over (decision 425): a last copy if the VPS still
// answers, stage it, start the standby, open its ports and point HardyOS at
// it, point DNS here, then watch peers come back. A failure before DNS
// changed undoes the local steps; after, the standby keeps running and the
// error says what's left.
func (s *Service) TakeOver(ctx context.Context, b Backend, a TakeOverArgs, p Progress) (*TakeoverRecord, error) {
	if p == nil {
		p = func(float64, string) {}
	}
	set, err := s.Settings(ctx)
	if err != nil {
		return nil, err
	}
	st, err := b.Status(ctx)
	if err != nil {
		return nil, err
	}
	name, hasAAAA, err := b.DNSStandby(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.CheckTakeOver(st, set, name, hasAAAA, a); err != nil {
		return nil, err
	}
	rec := &TakeoverRecord{At: s.now(), By: a.By, IPv4: set.PublicIPv4, IPv6: set.PublicIPv6, Notes: []string{}}
	if !a.SkipFinalSync {
		p(5, "Getting a last copy from the VPS (if it still answers)")
		sctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		_, err := b.Sync(sctx)
		cancel()
		if err != nil {
			rec.FinalSyncError = clip(err.Error(), 300)
			rec.Notes = append(rec.Notes, "The VPS didn't give a last copy ("+rec.FinalSyncError+"); the newest saved copy is used.")
		} else {
			rec.FinalSync = true
		}
		if st, err = b.Status(ctx); err != nil {
			return nil, err
		}
		if len(st.Snapshots) == 0 {
			return nil, &Problem{Msg: "there is no copy of the VPS to take over with"}
		}
		if _, newer := VersionNote(st.Snapshots[0].Info.Version); newer && !a.AcceptVersion {
			return nil, fmt.Errorf("%w: the VPS runs NetBird %s, newer than the standby's %s", ErrVersion, st.Snapshots[0].Info.Version, StandbyVersion)
		}
	}
	p(20, "Putting the copy into the standby")
	staged, err := b.Stage(ctx, st.Hostname)
	if err != nil {
		return nil, err
	}
	rec.SnapshotAt = staged.Snapshot.At
	undo := func(steps ...func() error) {
		for _, f := range steps {
			if err := f(); err != nil {
				rec.Notes = append(rec.Notes, "Undoing: "+clip(err.Error(), 200))
			}
		}
	}
	unstage := func() error { return b.Unstage(context.WithoutCancel(ctx), st.Hostname) }
	stop := func() error { return b.AppStop(context.WithoutCancel(ctx)) }
	closeNet := func() error { return b.Network(context.WithoutCancel(ctx), false) }
	p(35, "Starting the standby NetBird server")
	if err := b.AppUp(ctx); err != nil {
		undo(stop, unstage)
		return nil, fmt.Errorf("the standby didn't start: %w", err)
	}
	p(50, "Opening the NetBird ports and pointing this server at its own standby")
	if err := b.Network(ctx, true); err != nil {
		undo(stop, unstage)
		return nil, fmt.Errorf("the firewall couldn't be opened: %w", err)
	}
	p(60, "Pointing "+st.Hostname+" at this server in Cloudflare")
	if err := b.DNSSet(ctx, "A", set.PublicIPv4); err != nil {
		undo(closeNet, stop, unstage)
		return nil, fmt.Errorf("DNS wasn't changed: %w", err)
	}
	rec.DNSChanged = true
	if set.PublicIPv6 != "" {
		if err := b.DNSSet(ctx, "AAAA", set.PublicIPv6); err != nil {
			// The A record already points here: keep the standby running.
			rec.Notes = append(rec.Notes, "The AAAA record couldn't be set ("+clip(err.Error(), 200)+"); IPv6 clients may still go to the VPS.")
		}
	}
	if err := s.saveTakeover(ctx, rec); err != nil {
		return rec, err
	}
	p(75, "Waiting for peers to reconnect (DNS TTL is 60 s)")
	s.watchPeers(ctx, b, rec, p)
	p(100, "HardyOS has taken over")
	return rec, s.saveTakeover(context.WithoutCancel(ctx), rec)
}

func (s *Service) watchPeers(ctx context.Context, b Backend, rec *TakeoverRecord, p Progress) {
	wait, poll := s.PeerWait, s.PeerPoll
	if wait == 0 {
		wait = 3 * time.Minute
	}
	if poll == 0 {
		poll = 10 * time.Second
	}
	deadline := time.Now().Add(wait)
	for {
		total, conn, err := b.Peers(ctx)
		rec.PeersCheckedAt = s.now()
		if err != nil {
			rec.PeersProblem = clip(err.Error(), 200)
			if errors.Is(err, ErrNoPeerCheck) {
				return
			}
		} else {
			rec.PeersTotal, rec.PeersConnected, rec.PeersProblem = total, conn, ""
			p(75+20*float64(conn)/float64(max(total, 1)), fmt.Sprintf("%d of %d peers connected", conn, total))
			if total > 0 && conn >= total {
				return
			}
		}
		if time.Now().After(deadline) {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(poll):
		}
	}
}

// HandBackArgs are the administrator's choices.
type HandBackArgs struct {
	Confirm string `json:"confirm"`
	// AcceptSplitBrain: the administrator read that changes made on the VPS
	// since the take-over are replaced by the standby's.
	AcceptSplitBrain bool `json:"acceptSplitBrain"`
	// Discard: go back without sending the standby's state to the VPS
	// (changes made during the take-over are lost; the VPS keeps its own).
	Discard bool `json:"discard"`
}

// HandBackResult says what happened.
type HandBackResult struct {
	VPSMessage string   `json:"vpsMessage"`
	Bytes      int64    `json:"bytes"`
	Notes      []string `json:"notes"`
}

// HandBack gives the NetBird server back to the VPS (decision 427): the VPS
// must answer and allow restore; the standby stops, its databases go to the
// VPS (which keeps its own copy first), DNS goes back, the ports close and
// the staged state is removed. A failure before DNS changed starts the
// standby again.
func (s *Service) HandBack(ctx context.Context, b Backend, a HandBackArgs, p Progress) (*HandBackResult, error) {
	if p == nil {
		p = func(float64, string) {}
	}
	st, err := b.Status(ctx)
	if err != nil {
		return nil, err
	}
	switch {
	case st.Mode != ModeTakenOver:
		return nil, &Problem{Msg: "HardyOS hasn't taken over"}
	case strings.ToLower(strings.TrimSpace(a.Confirm)) != st.Hostname:
		return nil, &Problem{Msg: "type the NetBird server's name (" + st.Hostname + ") to hand back"}
	case !a.AcceptSplitBrain:
		return nil, &Problem{Msg: "confirm that the standby's state replaces the VPS's"}
	}
	out := &HandBackResult{Notes: []string{}}
	rec, _ := s.Takeover(ctx)
	if !a.Discard {
		p(5, "Asking the VPS how it is")
		vs, err := b.VPS(ctx)
		if err != nil {
			return nil, fmt.Errorf("the VPS doesn't answer, so it can't take NetBird back yet: %w", err)
		}
		if !vs.RestoreAllowed {
			return nil, &Problem{Msg: "the VPS doesn't allow hand-back: run HardyOS's VPS script there again with --allow-handback"}
		}
		if vs.Hostname != "" && vs.Hostname != st.Hostname {
			return nil, &Problem{Msg: "the VPS is set up for " + vs.Hostname + ", not " + st.Hostname}
		}
		if note, _ := VersionNote(vs.Version); note != "" {
			out.Notes = append(out.Notes, note)
		}
	}
	p(15, "Stopping the standby")
	if err := b.AppStop(ctx); err != nil {
		return nil, err
	}
	restart := func() {
		if err := b.AppUp(context.WithoutCancel(ctx)); err != nil {
			out.Notes = append(out.Notes, "The standby didn't start again: "+clip(err.Error(), 200))
		}
	}
	if !a.Discard {
		p(30, "Sending the standby's NetBird state to the VPS (it keeps a copy of its own first)")
		res, err := b.Handback(ctx, st.Hostname)
		if err != nil {
			restart()
			return nil, fmt.Errorf("the VPS didn't take the state back (the standby is running again): %w", err)
		}
		out.VPSMessage, out.Bytes = res.Message, res.Bytes
	}
	if rec == nil || rec.DNSChanged {
		p(70, "Pointing "+st.Hostname+" back at the VPS")
		if err := b.DNSRestore(ctx); err != nil {
			restart()
			return nil, fmt.Errorf("DNS couldn't be put back (the standby is running again; the VPS has the state too, so set the record in Cloudflare by hand or try again): %w", err)
		}
	}
	p(85, "Closing the standby's ports")
	if err := b.Network(ctx, false); err != nil {
		out.Notes = append(out.Notes, "The firewall couldn't be closed: "+clip(err.Error(), 200))
	}
	p(92, "Removing the take-over's state from the standby")
	if err := b.Unstage(ctx, st.Hostname); err != nil {
		return out, err
	}
	_ = s.saveTakeover(context.WithoutCancel(ctx), nil)
	p(100, "The VPS runs NetBird again")
	return out, nil
}
