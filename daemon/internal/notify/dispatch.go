package notify

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/store"
)

// Settings are the dispatcher's rules beyond routing.
type Settings struct {
	QuietHours QuietHours `json:"quietHours"`
	// DedupMinutes: the same alert (kind, title and text) within this many
	// minutes is dropped everywhere. 0 turns it off.
	DedupMinutes int `json:"dedupMinutes"`
	// MaxPerHour: each channel gets at most this many alerts of one kind
	// about one thing (kind + link) an hour; critical ones twice as many.
	// The next one sent says how many were held back.
	MaxPerHour int `json:"maxPerHour"`
	// ServerURL is the desktop's address for links in messages
	// (https://nas.example.com); empty leaves links out.
	ServerURL string `json:"serverUrl"`
}

// QuietHours hold back alerts to channels (not the desktop) at night and
// send them as one summary when quiet hours end. Alerts at Allow or above
// still go out at once.
type QuietHours struct {
	Enabled bool   `json:"enabled"`
	Start   string `json:"start"` // "22:00", server's local time
	End     string `json:"end"`   // "07:00"
	Allow   string `json:"allow"` // "critical" (default) or "warning"
}

// DefaultSettings are used until an administrator changes them.
func DefaultSettings() Settings {
	return Settings{
		QuietHours:   QuietHours{Start: "22:00", End: "07:00", Allow: SeverityCritical},
		DedupMinutes: 30,
		MaxPerHour:   6,
	}
}

const settingsKey = "notify.settings"

var clockRE = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)

// Validate checks settings.
func (s Settings) Validate() error {
	if s.DedupMinutes < 0 || s.DedupMinutes > 1440 {
		return invalid("dedupMinutes must be between 0 and 1440")
	}
	if s.MaxPerHour < 1 || s.MaxPerHour > 120 {
		return invalid("maxPerHour must be between 1 and 120")
	}
	q := s.QuietHours
	if !clockRE.MatchString(q.Start) || !clockRE.MatchString(q.End) {
		return invalid("quiet hours are times like 22:00")
	}
	if q.Allow != SeverityWarning && q.Allow != SeverityCritical {
		return invalid("quiet hours let through warning or critical alerts")
	}
	if s.ServerURL != "" {
		u, err := url.Parse(s.ServerURL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || len(s.ServerURL) > 300 {
			return invalid("the server address must be like https://nas.example.com")
		}
	}
	return nil
}

func minutesOf(hhmm string) int {
	h, _ := strconv.Atoi(hhmm[:2])
	m, _ := strconv.Atoi(hhmm[3:])
	return h*60 + m
}

// Active reports whether quiet hours are on at t (in t's location).
func (q QuietHours) Active(t time.Time) bool {
	if !q.Enabled || !clockRE.MatchString(q.Start) || !clockRE.MatchString(q.End) {
		return false
	}
	start, end, now := minutesOf(q.Start), minutesOf(q.End), t.Hour()*60+t.Minute()
	switch {
	case start == end:
		return false
	case start < end:
		return now >= start && now < end
	default: // over midnight
		return now >= start || now < end
	}
}

// Delivery is one line of the delivery log.
type Delivery struct {
	ID        int64     `json:"id"`
	At        time.Time `json:"at"`
	ChannelID int64     `json:"channelId"`
	Kind      string    `json:"kind"`
	Severity  string    `json:"severity"`
	Title     string    `json:"title"`
	Status    string    `json:"status"` // sent, failed, held, suppressed
	Detail    string    `json:"detail"`
}

type bucket struct {
	tokens float64
	last   time.Time
	held   int
}

type delivery struct {
	ch      *channelRow
	m       message
	attempt int
	done    chan error // a test waits for the outcome
}

// Dispatcher is the entry point for every event: Notify routes it to the
// desktop and the channels.
type Dispatcher struct {
	DB       *store.DB
	Center   *Center
	Channels *Channels
	Log      *slog.Logger
	// Hostname names this server in messages (default os.Hostname).
	Hostname func() string
	// Now is the clock (tests).
	Now func() time.Time

	// For tests: talk to httptest servers on loopback, trust a test CA for
	// SMTP, point SES elsewhere, skip retry delays.
	allowLocal  bool
	smtpTLS     *tls.Config
	sesEndpoint func(region string) string
	retryDelay  func(attempt int) time.Duration

	once    sync.Once
	queue   chan delivery
	mu      sync.Mutex
	recent  map[string]time.Time
	buckets map[string]*bucket
	httpc   *http.Client
}

func (d *Dispatcher) init() {
	d.once.Do(func() {
		d.queue = make(chan delivery, 512)
		d.recent = map[string]time.Time{}
		d.buckets = map[string]*bucket{}
	})
}

func (d *Dispatcher) log() *slog.Logger {
	if d.Log != nil {
		return d.Log
	}
	return slog.Default()
}

func (d *Dispatcher) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

func (d *Dispatcher) client() *http.Client {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.httpc == nil {
		d.httpc = guardedClient(d.allowLocal)
	}
	return d.httpc
}

var osHostname = os.Hostname

func (d *Dispatcher) hostname() string {
	if d.Hostname != nil {
		return d.Hostname()
	}
	h, err := osHostname()
	if err != nil || h == "" {
		return "HardyOS"
	}
	return h
}

// Settings returns the current settings.
func (d *Dispatcher) Settings(ctx context.Context) Settings {
	s := DefaultSettings()
	if raw, err := d.DB.GetSetting(ctx, settingsKey); err == nil {
		_ = json.Unmarshal([]byte(raw), &s)
	}
	return s
}

// SaveSettings validates and stores settings.
func (d *Dispatcher) SaveSettings(ctx context.Context, s Settings) (Settings, error) {
	if err := s.Validate(); err != nil {
		return s, err
	}
	s.ServerURL = strings.TrimSuffix(s.ServerURL, "/")
	b, _ := json.Marshal(s)
	return s, d.DB.SetSetting(ctx, settingsKey, string(b))
}

// Notify routes an event: the entry point every package uses. It never
// blocks on a channel; delivery happens in the background.
func (d *Dispatcher) Notify(ctx context.Context, e Event) {
	e = e.normalize()
	d.dispatch(ctx, e, levelFor(e.Severity), Category(e.Kind))
}

// legacyKinds give Center.Send's sources an event kind.
var legacyKinds = map[string]string{"storage": "pool.notice", "updates": "system.update", "backups": "backup.settings"}

// Forward is Center.Forward: notifications from packages that predate
// events go through routing too, keeping their level (success stays
// green on the desktop).
func (d *Dispatcher) Forward(ctx context.Context, n Notification) {
	kind := legacyKinds[n.Source]
	if kind == "" {
		kind = oneLine(n.Source) + ".notice"
		if n.Source == "" {
			kind = "system.notice"
		}
	}
	e := Event{Kind: kind, Severity: severityFor(n.Level), Title: n.Title, Body: n.Body, Link: n.Link, Time: n.At}.normalize()
	src := n.Source
	if src == "" {
		src = Category(kind)
	}
	d.dispatch(ctx, e, n.Level, src)
}

// duplicate reports (and remembers) whether the same alert was seen within
// the dedup window.
func (d *Dispatcher) duplicate(e Event, s Settings) bool {
	if s.DedupMinutes == 0 {
		return false
	}
	key := e.Kind + "\x00" + e.Severity + "\x00" + e.Title + "\x00" + e.Body
	now := d.now()
	window := time.Duration(s.DedupMinutes) * time.Minute
	d.mu.Lock()
	defer d.mu.Unlock()
	for k, t := range d.recent {
		if now.Sub(t) > window {
			delete(d.recent, k)
		}
	}
	if t, ok := d.recent[key]; ok && now.Sub(t) < window {
		return true
	}
	d.recent[key] = now
	return false
}

// take spends a token from a channel's bucket for one alert subject and
// returns how many were held back before it.
func (d *Dispatcher) take(key, severity string, s Settings) (bool, int) {
	capacity := float64(s.MaxPerHour)
	if severity == SeverityCritical {
		capacity *= 2
	}
	now := d.now()
	d.mu.Lock()
	defer d.mu.Unlock()
	b := d.buckets[key]
	if b == nil {
		b = &bucket{tokens: capacity, last: now}
		d.buckets[key] = b
	}
	b.tokens += now.Sub(b.last).Hours() * capacity
	if b.tokens > capacity {
		b.tokens = capacity
	}
	b.last = now
	if b.tokens < 1 {
		b.held++
		return false, 0
	}
	b.tokens--
	held := b.held
	b.held = 0
	return true, held
}

func (d *Dispatcher) message(e Event, s Settings) message {
	return message{Event: e, Server: d.hostname(), ServerURL: s.ServerURL}
}

func (d *Dispatcher) dispatch(ctx context.Context, e Event, level Level, source string) {
	d.init()
	ctx = context.WithoutCancel(ctx)
	s := d.Settings(ctx)
	if d.duplicate(e, s) {
		d.log().Debug("duplicate alert dropped", "kind", e.Kind, "title", e.Title)
		return
	}
	targets, err := d.Channels.targets(ctx, e.Kind, e.Severity)
	if err != nil {
		d.log().Error("alert routing failed; showing it on the desktop", "err", err)
		targets = []*channelRow{{Channel: Channel{Type: TypeDesktop}}}
	}
	quiet := s.QuietHours.Active(d.now().Local()) && SeverityRank(e.Severity) < SeverityRank(s.QuietHours.Allow)
	for _, ch := range targets {
		if ch.Type == TypeDesktop {
			n := Notification{At: e.Time, Level: level, Title: e.Title, Body: e.Body, Source: source, AdminOnly: true, Kind: e.Kind, Link: e.Link}
			if err := d.Center.Store(ctx, n); err != nil {
				d.log().Error("desktop notification failed", "err", err)
			}
			continue
		}
		ok, held := d.take(strconv.FormatInt(ch.ID, 10)+"\x00"+e.Kind+"\x00"+e.Link, e.Severity, s)
		if !ok {
			d.record(ctx, ch.ID, e, "suppressed", "more than the hourly limit for this alert")
			continue
		}
		m := d.message(e, s)
		if held > 0 {
			m.Note = fmt.Sprintf("%d similar alert(s) were held back during the last hour.", held)
		}
		if quiet {
			var held int
			_ = d.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM notify_deferred WHERE channel_id = ?`, ch.ID).Scan(&held)
			if held >= MaxDeferred {
				d.record(ctx, ch.ID, e, "suppressed", "quiet hours: already holding the most alerts kept for the summary")
				continue
			}
			if _, err := d.DB.ExecContext(ctx, `INSERT INTO notify_deferred (channel_id, at, kind, severity, title, body, link) VALUES (?, ?, ?, ?, ?, ?, ?)`,
				ch.ID, store.FormatTime(e.Time), e.Kind, e.Severity, e.Title, e.Body, e.Link); err == nil {
				d.record(ctx, ch.ID, e, "held", "quiet hours")
				continue
			}
		}
		d.enqueue(delivery{ch: ch, m: m})
	}
}

func (d *Dispatcher) enqueue(dl delivery) {
	d.init()
	select {
	case d.queue <- dl:
	default:
		d.log().Warn("alert queue full; dropping", "channel", dl.ch.ID, "title", dl.m.Title)
		if dl.done != nil {
			dl.done <- errors.New("the alert queue is full")
		}
	}
}

func (d *Dispatcher) record(ctx context.Context, channelID int64, e Event, status, detail string) {
	res, err := d.DB.ExecContext(ctx, `INSERT INTO notify_deliveries (at, channel_id, kind, severity, title, status, detail) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		store.Now(), channelID, e.Kind, e.Severity, e.Title, status, clip(detail, 500))
	if err != nil {
		return
	}
	if id, _ := res.LastInsertId(); id > 500 {
		_, _ = d.DB.ExecContext(ctx, `DELETE FROM notify_deliveries WHERE id <= ?`, id-500)
	}
}

// Deliveries returns the newest delivery log entries.
func (d *Dispatcher) Deliveries(ctx context.Context, limit int) ([]Delivery, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := d.DB.QueryContext(ctx, `SELECT id, at, channel_id, kind, severity, title, status, detail FROM notify_deliveries ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Delivery{}
	for rows.Next() {
		var x Delivery
		var at string
		if err := rows.Scan(&x.ID, &at, &x.ChannelID, &x.Kind, &x.Severity, &x.Title, &x.Status, &x.Detail); err != nil {
			return nil, err
		}
		x.At = store.ParseTime(at)
		out = append(out, x)
	}
	return out, rows.Err()
}

func (d *Dispatcher) send(ctx context.Context, ch *channelRow, m message) error {
	switch ch.Type {
	case TypeDiscord, TypeSlack, TypeTeams, TypeWebhook:
		return d.sendWebhook(ctx, ch, m)
	case TypeSMTP:
		return d.sendSMTP(ctx, ch, m)
	case TypeSES:
		return d.sendSES(ctx, ch, m)
	}
	return &sendError{Msg: "unknown channel type " + ch.Type}
}

func (d *Dispatcher) delay(attempt int) time.Duration {
	if d.retryDelay != nil {
		return d.retryDelay(attempt)
	}
	return []time.Duration{0, 30 * time.Second, 2 * time.Minute, 10 * time.Minute}[min(attempt, 3)]
}

const maxAttempts = 3

// MaxDeferred is how many alerts quiet hours hold per channel.
const MaxDeferred = 1000

// pruneBuckets forgets rate-limit buckets that have refilled (nothing
// sent about that subject for two hours).
func (d *Dispatcher) pruneBuckets() {
	now := d.now()
	d.mu.Lock()
	defer d.mu.Unlock()
	for k, b := range d.buckets {
		if now.Sub(b.last) > 2*time.Hour {
			delete(d.buckets, k)
		}
	}
}

func (d *Dispatcher) deliver(ctx context.Context, dl delivery) {
	sctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	err := d.send(sctx, dl.ch, dl.m)
	cancel()
	dl.attempt++
	if err != nil && temporary(err) && dl.attempt < maxAttempts && dl.done == nil {
		d.log().Info("alert delivery failed; trying again", "channel", dl.ch.ID, "attempt", dl.attempt, "err", err)
		time.AfterFunc(d.delay(dl.attempt), func() { d.enqueue(dl) })
		return
	}
	d.Channels.recordResult(ctx, dl.ch.ID, err)
	if err != nil {
		d.log().Warn("alert delivery failed", "channel", dl.ch.ID, "type", dl.ch.Type, "err", err)
		d.record(ctx, dl.ch.ID, dl.m.Event, "failed", err.Error())
	} else {
		d.record(ctx, dl.ch.ID, dl.m.Event, "sent", "")
	}
	if dl.done != nil {
		dl.done <- err
	}
}

// Run delivers queued alerts and sends quiet-hours summaries until ctx is
// done.
func (d *Dispatcher) Run(ctx context.Context) {
	d.init()
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case dl := <-d.queue:
					d.deliver(ctx, dl)
				}
			}
		}()
	}
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case <-t.C:
			d.flushQuiet(ctx)
			d.pruneBuckets()
		}
	}
}

// flushQuiet sends one summary per channel of what quiet hours held back,
// once they're over.
func (d *Dispatcher) flushQuiet(ctx context.Context) {
	s := d.Settings(ctx)
	if s.QuietHours.Active(d.now().Local()) {
		return
	}
	rows, err := d.DB.QueryContext(ctx, `SELECT id, channel_id, severity, title FROM notify_deferred ORDER BY id`)
	if err != nil {
		return
	}
	type held struct {
		ids    []int64
		lines  []string
		maxSev string
	}
	per := map[int64]*held{}
	var order []int64
	for rows.Next() {
		var id, ch int64
		var sev, title string
		if rows.Scan(&id, &ch, &sev, &title) != nil {
			continue
		}
		h := per[ch]
		if h == nil {
			h = &held{maxSev: SeverityInfo}
			per[ch] = h
			order = append(order, ch)
		}
		h.ids = append(h.ids, id)
		if len(h.lines) < 25 {
			h.lines = append(h.lines, "• "+sevLabel[sev]+": "+title)
		}
		if SeverityRank(sev) > SeverityRank(h.maxSev) {
			h.maxSev = sev
		}
	}
	rows.Close()
	for _, chID := range order {
		h := per[chID]
		for _, id := range h.ids {
			_, _ = d.DB.ExecContext(ctx, `DELETE FROM notify_deferred WHERE id = ?`, id)
		}
		ch, err := d.Channels.get(ctx, chID, true)
		if err != nil || !ch.Enabled {
			continue
		}
		body := strings.Join(h.lines, "\n")
		if extra := len(h.ids) - len(h.lines); extra > 0 {
			body += fmt.Sprintf("\n…and %d more. See the desktop's notifications.", extra)
		}
		e := Event{Kind: "system.quiet_hours", Severity: h.maxSev, Title: fmt.Sprintf("%d alert(s) while quiet hours were on", len(h.ids)), Body: body}.normalize()
		d.enqueue(delivery{ch: ch, m: d.message(e, s)})
	}
}

// Test sends a test message to one channel now, ignoring routing, limits
// and quiet hours, and returns the outcome.
func (d *Dispatcher) Test(ctx context.Context, id int64) error {
	d.init()
	ch, err := d.Channels.get(ctx, id, true)
	if err != nil {
		return err
	}
	e := Event{Kind: "system.test", Severity: SeverityInfo, Title: "Test alert from HardyOS",
		Body: "If you can read this, alerts reach this channel (" + ch.Name + ").", Link: "control/notifications"}.normalize()
	if ch.Type == TypeDesktop {
		return d.Center.Store(ctx, Notification{At: e.Time, Level: Info, Title: e.Title, Body: e.Body, Source: "system", AdminOnly: true, Kind: e.Kind, Link: e.Link})
	}
	done := make(chan error, 1)
	dl := delivery{ch: ch, m: d.message(e, d.Settings(ctx)), done: done}
	d.deliver(ctx, dl)
	return <-done
}
