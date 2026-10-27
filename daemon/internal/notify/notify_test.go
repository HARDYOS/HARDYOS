package notify

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/events"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

func newTestDispatcher(t *testing.T) (*Dispatcher, *store.DB) {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "n.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	center := &Center{DB: db, Events: events.NewBroker()}
	d := &Dispatcher{DB: db, Center: center, Channels: &Channels{DB: db}, Hostname: func() string { return "nas" }}
	center.Forward = d.Forward
	d.retryDelay = func(int) time.Duration { return time.Millisecond }
	return d, db
}

// hook is an httptest server that records what was posted.
type hook struct {
	*httptest.Server
	mu     sync.Mutex
	bodies []string
	status int
}

func newHook(t *testing.T) *hook {
	h := &hook{status: http.StatusNoContent}
	h.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		h.mu.Lock()
		h.bodies = append(h.bodies, string(b))
		st := h.status
		h.mu.Unlock()
		w.WriteHeader(st)
	}))
	t.Cleanup(h.Close)
	return h
}

func (h *hook) got() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.bodies...)
}

func strp(s string) *string { return &s }

func TestWebhookURLRules(t *testing.T) {
	cases := []struct {
		typ, url string
		any      bool
		ok       bool
	}{
		{TypeDiscord, "https://discord.com/api/webhooks/1/abc", false, true},
		{TypeDiscord, "https://discordapp.com/api/webhooks/1/abc", false, true},
		{TypeDiscord, "http://discord.com/api/webhooks/1/abc", false, false},
		{TypeDiscord, "https://discord.com.evil.example/api/webhooks/1/abc", false, false},
		{TypeDiscord, "https://discord.com:8443/api/webhooks/1/abc", false, false},
		{TypeDiscord, "https://user:pw@discord.com/api/webhooks/1/abc", false, false},
		{TypeSlack, "https://hooks.slack.com/services/T/B/x", false, true},
		{TypeSlack, "https://slack.com/services/T/B/x", false, false},
		{TypeTeams, "https://contoso.webhook.office.com/webhookb2/x", false, true},
		{TypeTeams, "https://prod-01.westus.logic.azure.com:443/workflows/abc/triggers/manual/paths/invoke?sig=x", false, true},
		{TypeTeams, "https://teams.example.com/hook", false, false},
		{TypeWebhook, "https://alerts.example.com/hook", false, false}, // needs the explicit opt-in
		{TypeWebhook, "https://alerts.example.com:8443/hook", true, true},
		{TypeWebhook, "https://127.0.0.1/hook", true, false},
		{TypeWebhook, "https://192.168.1.10/hook", true, false},
		{TypeWebhook, "https://100.64.3.4/hook", true, false},
		{TypeWebhook, "https://[::1]/hook", true, false},
		{TypeWebhook, "https://[fd00::1]/hook", true, false},
		{TypeWebhook, "https://localhost/hook", true, false},
		{TypeWebhook, "https://nas.local/hook", true, false},
		{TypeWebhook, "ftp://alerts.example.com/hook", true, false},
	}
	for _, c := range cases {
		_, err := checkWebhookURL(c.typ, c.url, c.any)
		if (err == nil) != c.ok {
			t.Errorf("%s %s any=%v: err %v, want ok=%v", c.typ, c.url, c.any, err, c.ok)
		}
	}
}

func TestPublicAddr(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "10.1.2.3", "172.20.0.1", "192.168.0.1", "100.100.1.1", "169.254.169.254", "0.0.0.0", "::1", "fe80::1", "fc00::1", "::ffff:127.0.0.1", "64:ff9b::a00:1", "224.0.0.1", "198.18.0.1",
		"::7f00:1", "::a00:1", "2002:7f00:1::1", "2002:c0a8:101::1", "fec0::1", "2002:0a00:0001::"} {
		if publicAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s counted as public", s)
		}
	}
	for _, s := range []string{"1.1.1.1", "162.159.135.232", "2606:4700::1111", "2002:0101:0101::1"} {
		if !publicAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s counted as local", s)
		}
	}
}

func TestGuardRefusesLoopback(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("request reached a loopback server") }))
	defer srv.Close()
	err := postJSON(t.Context(), guardedClient(false), srv.URL+"/api/webhooks/1/SECRETTOKEN", []byte(`{}`), nil)
	var le *LocalAddressError
	if !errors.As(scrubURL(err), &le) && !strings.Contains(err.Error(), "private network") {
		t.Fatalf("want a local address error, got %v", err)
	}
	if temporary(err) {
		t.Error("a refused address must not be retried")
	}
	if strings.Contains(err.Error(), "SECRETTOKEN") {
		t.Errorf("the webhook URL leaked into the error: %v", err)
	}
}

func TestRedirectNotFollowed(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("redirect followed") }))
	defer target.Close()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	c := guardedClient(true)
	c.Transport.(*http.Transport).TLSClientConfig = srv.Client().Transport.(*http.Transport).TLSClientConfig
	err := postJSON(t.Context(), c, srv.URL+"/x", []byte(`{}`), nil)
	if err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("want a redirect error, got %v", err)
	}
}

// addHook creates a channel pointing at a test server (bypassing the URL
// rules, which need real Discord/Slack hosts).
func addHook(t *testing.T, d *Dispatcher, typ string, h *hook) int64 {
	t.Helper()
	ch, err := d.Channels.Create(t.Context(), ChannelInput{Type: TypeWebhook, Name: typ, Config: ChannelConfig{AllowAnyHost: true}, Secrets: &SecretsInput{URL: strp("https://alerts.example.com/hook")}})
	if err != nil {
		t.Fatal(err)
	}
	cfg, _ := json.Marshal(ChannelConfig{AllowAnyHost: true, URLHost: "127.0.0.1"})
	sealed, err := d.Channels.seal(t.Context(), ch.ID, Secrets{URL: h.URL + "/api/webhooks/1/tok"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.DB.Exec(`UPDATE notify_channels SET type = ?, config = ?, secrets = ? WHERE id = ?`, typ, string(cfg), sealed, ch.ID); err != nil {
		t.Fatal(err)
	}
	return ch.ID
}

func testClient(d *Dispatcher, h *hook) {
	d.allowLocal = true
	d.httpc = h.Client()
	d.httpc.CheckRedirect = func(*http.Request, []*http.Request) error { return errRedirect }
}

func TestWebhookPayloads(t *testing.T) {
	m := message{Event: Event{Kind: "disk.smart", Severity: SeverityWarning, Title: "Disk sda <is> failing", Body: "8 reallocated sectors @everyone", Link: "storage/disks", Time: time.Unix(1_800_000_000, 0)}, Server: "nas", ServerURL: "https://nas.example.com"}
	var dsc map[string]any
	if err := json.Unmarshal(discordPayload(m), &dsc); err != nil {
		t.Fatal(err)
	}
	embed := dsc["embeds"].([]any)[0].(map[string]any)
	if embed["title"] != `Disk sda \<is\> failing` || embed["url"] != "https://nas.example.com/#open=storage/disks" || embed["color"].(float64) != 0xF59E0B {
		t.Errorf("discord embed %v", embed)
	}
	if am := dsc["allowed_mentions"].(map[string]any); len(am["parse"].([]any)) != 0 {
		t.Error("discord payload allows mentions")
	}
	m.Body = "a <b> & c"
	var slack struct {
		Blocks []struct {
			Text struct{ Text string } `json:"text"`
		} `json:"blocks"`
	}
	if err := json.Unmarshal(slackPayload(m), &slack); err != nil {
		t.Fatal(err)
	}
	if slack.Blocks[0].Text.Text != "Disk sda <is> failing" || slack.Blocks[1].Text.Text != "a &lt;b&gt; &amp; c" {
		t.Errorf("slack blocks %+v", slack.Blocks)
	}
	var teams map[string]any
	if err := json.Unmarshal(teamsPayload(m), &teams); err != nil {
		t.Fatal(err)
	}
	att := teams["attachments"].([]any)[0].(map[string]any)
	if att["contentType"] != "application/vnd.microsoft.card.adaptive" {
		t.Errorf("teams attachment %v", att)
	}
}

func TestRoutingDedupAndRateLimit(t *testing.T) {
	d, db := newTestDispatcher(t)
	h := newHook(t)
	testClient(d, h)
	id := addHook(t, d, TypeWebhook, h)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go d.Run(ctx)

	// New channels get warning and up for every category.
	d.Notify(ctx, Event{Kind: "pool.capacity", Severity: SeverityInfo, Title: "info only"})
	d.Notify(ctx, Event{Kind: "pool.capacity", Severity: SeverityWarning, Title: "tank is 81% full", Link: "storage/pool/tank"})
	d.Notify(ctx, Event{Kind: "pool.capacity", Severity: SeverityWarning, Title: "tank is 81% full", Link: "storage/pool/tank"}) // duplicate
	waitFor(t, func() bool { return len(h.got()) == 1 })
	if !strings.Contains(h.got()[0], "tank is 81% full") {
		t.Errorf("got %v", h.got())
	}
	// The desktop got both distinct events (info and warning), not the duplicate.
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM notifications`).Scan(&n)
	if n != 2 {
		t.Errorf("desktop has %d notifications, want 2", n)
	}

	// Routing: disk alerts only when critical on this channel.
	if err := d.Channels.SetRoutes(ctx, []Route{{"*", 1, SeverityInfo}, {"*", id, SeverityWarning}, {"disk", id, SeverityCritical}}); err != nil {
		t.Fatal(err)
	}
	d.Notify(ctx, Event{Kind: "disk.temperature", Severity: SeverityWarning, Title: "sda is hot"})
	if err := d.Channels.SetRoutes(ctx, []Route{{"*", 1, SeverityInfo}, {"*", id, SeverityWarning}, {"disk", id, SeverityCritical}, {"vm", id, RouteOff}}); err != nil {
		t.Fatal(err)
	}
	d.Notify(ctx, Event{Kind: "vm.crashed", Severity: SeverityCritical, Title: "haos crashed"})
	d.Notify(ctx, Event{Kind: "disk.smart", Severity: SeverityCritical, Title: "sda is failing"})
	waitFor(t, func() bool { return len(h.got()) == 2 })
	if strings.Contains(strings.Join(h.got(), ""), "sda is hot") || strings.Contains(strings.Join(h.got(), ""), "haos crashed") {
		t.Error("a warning reached a channel set to critical for disks")
	}

	// Rate limit: 6 an hour for one thing; the 7th is held back, and the
	// next one sent says so.
	now := time.Now()
	d.Now = func() time.Time { return now }
	for i := range 8 {
		d.Notify(ctx, Event{Kind: "app.crashed", Severity: SeverityWarning, Title: "immich crashed", Body: strings.Repeat("x", i+1), Link: "apps/immich"})
	}
	waitFor(t, func() bool { return len(h.got()) == 2+6 })
	time.Sleep(50 * time.Millisecond)
	if len(h.got()) != 8 {
		t.Errorf("rate limit let %d through", len(h.got())-2)
	}
	now = now.Add(30 * time.Minute)
	d.Notify(ctx, Event{Kind: "app.crashed", Severity: SeverityWarning, Title: "immich crashed", Body: "again", Link: "apps/immich"})
	waitFor(t, func() bool { return len(h.got()) == 9 })
	if !strings.Contains(h.got()[8], "2 similar alert(s) were held back") {
		t.Errorf("held-back note missing: %s", h.got()[8])
	}
	ds, _ := d.Deliveries(ctx, 50)
	var suppressed int
	for _, x := range ds {
		if x.Status == "suppressed" {
			suppressed++
		}
	}
	if suppressed != 2 {
		t.Errorf("%d suppressed deliveries logged, want 2", suppressed)
	}
}

func TestQuietHours(t *testing.T) {
	d, db := newTestDispatcher(t)
	h := newHook(t)
	testClient(d, h)
	addHook(t, d, TypeDiscord, h)
	at := time.Date(2026, 10, 27, 23, 30, 0, 0, time.Local)
	d.Now = func() time.Time { return at }
	s := DefaultSettings()
	s.QuietHours.Enabled = true
	if _, err := d.SaveSettings(t.Context(), s); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go d.Run(ctx)
	d.Notify(ctx, Event{Kind: "ups.power", Severity: SeverityWarning, Title: "On battery"})
	d.Notify(ctx, Event{Kind: "pool.health", Severity: SeverityCritical, Title: "tank faulted"})
	waitFor(t, func() bool { return len(h.got()) == 1 })
	if !strings.Contains(h.got()[0], "tank faulted") {
		t.Errorf("critical alert should pass quiet hours: %v", h.got())
	}
	var held int
	_ = db.QueryRow(`SELECT COUNT(*) FROM notify_deferred`).Scan(&held)
	if held != 1 {
		t.Fatalf("%d deferred, want 1", held)
	}
	d.flushQuiet(ctx) // still quiet: nothing
	at = time.Date(2026, 10, 28, 7, 1, 0, 0, time.Local)
	d.flushQuiet(ctx)
	waitFor(t, func() bool { return len(h.got()) == 2 })
	if !strings.Contains(h.got()[1], "while quiet hours were on") || !strings.Contains(h.got()[1], "On battery") {
		t.Errorf("summary %s", h.got()[1])
	}
}

func TestQuietHoursActive(t *testing.T) {
	q := QuietHours{Enabled: true, Start: "22:00", End: "07:00"}
	for _, c := range []struct {
		h, m int
		want bool
	}{{21, 59, false}, {22, 0, true}, {3, 0, true}, {6, 59, true}, {7, 0, false}, {12, 0, false}} {
		if got := q.Active(time.Date(2026, 1, 1, c.h, c.m, 0, 0, time.UTC)); got != c.want {
			t.Errorf("%02d:%02d active=%v", c.h, c.m, got)
		}
	}
	day := QuietHours{Enabled: true, Start: "09:00", End: "17:00"}
	if !day.Active(time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)) || day.Active(time.Date(2026, 1, 1, 18, 0, 0, 0, time.UTC)) {
		t.Error("daytime window wrong")
	}
}

func TestRetryThenFail(t *testing.T) {
	d, db := newTestDispatcher(t)
	h := newHook(t)
	h.status = http.StatusBadGateway
	testClient(d, h)
	id := addHook(t, d, TypeSlack, h)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go d.Run(ctx)
	d.Notify(ctx, Event{Kind: "vm.stopped", Severity: SeverityWarning, Title: "VM stopped"})
	waitFor(t, func() bool { return len(h.got()) == maxAttempts })
	waitFor(t, func() bool {
		var e string
		_ = db.QueryRow(`SELECT last_error FROM notify_channels WHERE id = ?`, id).Scan(&e)
		return strings.Contains(e, "502")
	})
}

func TestSecretsNeverListed(t *testing.T) {
	d, _ := newTestDispatcher(t)
	ch, err := d.Channels.Create(t.Context(), ChannelInput{Type: TypeDiscord, Name: "Family Discord",
		Secrets: &SecretsInput{URL: strp("https://discord.com/api/webhooks/123/TOPSECRET")}})
	if err != nil {
		t.Fatal(err)
	}
	if ch.Config.URLHost != "discord.com" || !ch.SecretsSet["url"] {
		t.Errorf("channel %+v", ch)
	}
	_, err = d.Channels.Create(t.Context(), ChannelInput{Type: TypeSMTP, Name: "Gmail",
		Config:  ChannelConfig{Host: "smtp.gmail.com", Username: "cade@gmail.com", From: "cade@gmail.com", To: []string{"cade@example.com"}},
		Secrets: &SecretsInput{Password: strp("abcd efgh ijkl mnop")}})
	if err != nil {
		t.Fatal(err)
	}
	list, _ := d.Channels.List(t.Context())
	b, _ := json.Marshal(list)
	for _, secret := range []string{"TOPSECRET", "abcd efgh", "webhooks/123"} {
		if strings.Contains(string(b), secret) {
			t.Errorf("%q in the channel list: %s", secret, b)
		}
	}
	var raw []byte
	_ = d.DB.QueryRow(`SELECT secrets FROM notify_channels WHERE id = ?`, ch.ID).Scan(&raw)
	if strings.Contains(string(raw), "TOPSECRET") {
		t.Error("secret stored in the clear")
	}
	// Updating without secrets keeps them; a moved row doesn't open.
	up, err := d.Channels.Update(t.Context(), ch.ID, ChannelInput{Name: "Discord"})
	if err != nil || !up.SecretsSet["url"] || up.Name != "Discord" {
		t.Fatalf("update: %+v %v", up, err)
	}
	if _, err := d.Channels.open(t.Context(), ch.ID+1, raw); err == nil {
		t.Error("sealed secrets opened for another row")
	}
	if err := d.Channels.Delete(t.Context(), 1); err == nil {
		t.Error("the desktop channel was deleted")
	}
}

func TestChannelValidation(t *testing.T) {
	d, _ := newTestDispatcher(t)
	bad := []ChannelInput{
		{Type: TypeSMTP, Name: "x", Config: ChannelConfig{Host: "smtp.gmail.com", From: "not-an-address", To: []string{"a@b.c"}}},
		{Type: TypeSMTP, Name: "x", Config: ChannelConfig{Host: "smtp gmail", From: "a@b.c", To: []string{"a@b.c"}}},
		{Type: TypeSMTP, Name: "x", Config: ChannelConfig{Host: "smtp.gmail.com", From: "a@b.c", To: []string{"a@b.c\r\nBcc: x@y.z"}}},
		{Type: TypeSMTP, Name: "x", Config: ChannelConfig{Host: "smtp.gmail.com", Username: "u", From: "a@b.c", To: []string{"a@b.c"}}}, // no password
		{Type: TypeSES, Name: "x", Config: ChannelConfig{Region: "mars-1", AccessKeyID: "AKIAEXAMPLEEXAMPLE", From: "a@b.c", To: []string{"a@b.c"}}, Secrets: &SecretsInput{SecretAccessKey: strp("k")}},
		{Type: TypeSES, Name: "x", Config: ChannelConfig{Region: "us-east-1", AccessKeyID: "AKIAEXAMPLEEXAMPLE", From: "a@b.c", To: []string{"a@b.c"}}},
		{Type: TypeWebhook, Name: "x", Secrets: &SecretsInput{URL: strp("https://example.com/h")}},
		{Type: TypeDesktop, Name: "x"},
		{Type: "pager", Name: "x"},
		{Type: TypeDiscord, Name: "", Secrets: &SecretsInput{URL: strp("https://discord.com/api/webhooks/1/a")}},
	}
	for i, in := range bad {
		if _, err := d.Channels.Create(t.Context(), in); err == nil {
			t.Errorf("case %d accepted: %+v", i, in)
		}
	}
	ses, err := d.Channels.Create(t.Context(), ChannelInput{Type: TypeSES, Name: "SES", Config: ChannelConfig{Region: "us-gov-west-1", AccessKeyID: "AKIAEXAMPLEEXAMPLE", From: "nas@example.com", To: []string{"a@example.com"}},
		Secrets: &SecretsInput{SecretAccessKey: strp("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY")}})
	if err != nil || ses.Config.Port != 0 || !ses.SecretsSet["secretAccessKey"] {
		t.Fatalf("SES channel: %+v %v", ses, err)
	}
}

func TestLegacyForwardAndPerUserRead(t *testing.T) {
	d, db := newTestDispatcher(t)
	ctx := t.Context()
	if _, err := db.Exec(`INSERT INTO users (id, username, display_name, password_hash, role, created_at, updated_at) VALUES (7, 'a', 'A', 'x', 'admin', 'now', 'now'), (8, 'b', 'B', 'x', 'admin', 'now', 'now')`); err != nil {
		t.Skipf("users table differs: %v", err)
	}
	if err := d.Center.Send(ctx, Notification{Level: Success, Title: "Pool tank is ready", Source: "storage", AdminOnly: true}); err != nil {
		t.Fatal(err)
	}
	list, _ := d.Center.ListFor(ctx, 7, true, 10)
	if len(list) != 1 || list[0].Level != Success || list[0].Kind != "pool.notice" {
		t.Fatalf("legacy notification %+v", list)
	}
	_ = d.Center.MarkRead(ctx, 7, 0, true)
	if n, _ := d.Center.Unread(ctx, 7, true); n != 0 {
		t.Errorf("user 7 unread %d", n)
	}
	if n, _ := d.Center.Unread(ctx, 8, true); n != 1 {
		t.Errorf("user 8 unread %d, want 1 (read state is per person)", n)
	}
	if n, _ := d.Center.Unread(ctx, 9, false); n != 0 {
		t.Errorf("a non-admin sees admin notifications: %d", n)
	}
}

func TestEventNormalize(t *testing.T) {
	e := Event{Severity: "panic", Title: "a\r\nBcc: x", Link: "x\ny"}.normalize()
	if e.Severity != SeverityInfo || strings.ContainsAny(e.Title, "\r\n") || e.Kind != "system.notice" || e.Time.IsZero() || strings.Contains(e.Link, "\n") {
		t.Errorf("normalize %+v", e)
	}
	if Category("disk.smart") != "disk" || Category("backup") != "backup" {
		t.Error("category")
	}
	var n Notifier = &Dispatcher{}
	_ = n
	Discard.Notify(context.Background(), Event{})
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestChatTextIsLiteral(t *testing.T) {
	m := message{Event: Event{Kind: "pool.data", Severity: SeverityCritical, Title: "Damaged: [x](https://evil)", Body: "file **[x](https://evil.example/a)** and https://evil.example/b @everyone",
		Link: "storage/pool/tank", Time: time.Unix(1_800_000_000, 0)}, Server: "nas", ServerURL: "https://nas.example.com"}
	var dsc struct {
		Embeds []struct{ Title, Description, URL string } `json:"embeds"`
	}
	if err := json.Unmarshal(discordPayload(m), &dsc); err != nil {
		t.Fatal(err)
	}
	e := dsc.Embeds[0]
	for _, s := range []string{e.Title, e.Description} {
		if strings.Contains(s, "[x](") || strings.Contains(s, "https://evil") || strings.Contains(s, "**") || strings.Contains(s, "@everyone") {
			t.Errorf("discord text still active: %q", s)
		}
	}
	if !strings.Contains(e.Description, `\[x\]\(https:`) || e.URL != "https://nas.example.com/#open=storage/pool/tank" {
		t.Errorf("discord %q %q", e.Description, e.URL)
	}
	teams := string(teamsPayload(m))
	if strings.Contains(teams, `"TextBlock"`) || !strings.Contains(teams, `"TextRun"`) || !strings.Contains(teams, `"url":"https://nas.example.com/#open=storage/pool/tank"`) {
		t.Errorf("teams %s", teams)
	}
	var slack struct {
		Blocks []struct {
			Text struct {
				Verbatim bool `json:"verbatim"`
			} `json:"text"`
		} `json:"blocks"`
	}
	_ = json.Unmarshal(slackPayload(m), &slack)
	if !slack.Blocks[1].Text.Verbatim {
		t.Error("slack body may auto-link")
	}
}

func TestDispatcherBounds(t *testing.T) {
	d, db := newTestDispatcher(t)
	h := newHook(t)
	testClient(d, h)
	id := addHook(t, d, TypeDiscord, h)
	now := time.Date(2026, 10, 27, 23, 30, 0, 0, time.Local)
	d.Now = func() time.Time { return now }
	s := DefaultSettings()
	s.QuietHours.Enabled, s.DedupMinutes, s.MaxPerHour = true, 0, 120
	_, _ = d.SaveSettings(t.Context(), s)
	_, _ = db.Exec(`INSERT INTO notify_deferred (channel_id, at, kind, severity, title) SELECT ?, 'x', 'k', 'warning', 't' FROM (WITH RECURSIVE c(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM c WHERE n < ?) SELECT n FROM c)`, id, MaxDeferred)
	d.Notify(t.Context(), Event{Kind: "ups.power", Severity: SeverityWarning, Title: "one too many", Link: "ups"})
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM notify_deferred WHERE channel_id = ?`, id).Scan(&n)
	if n != MaxDeferred {
		t.Errorf("%d deferred, cap %d", n, MaxDeferred)
	}
	d.mu.Lock()
	k := len(d.buckets)
	d.mu.Unlock()
	if k == 0 {
		t.Fatal("no bucket")
	}
	now = now.Add(3 * time.Hour)
	d.pruneBuckets()
	d.mu.Lock()
	k = len(d.buckets)
	d.mu.Unlock()
	if k != 0 {
		t.Errorf("%d buckets after pruning", k)
	}
}
