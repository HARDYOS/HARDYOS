package nbstandby

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The VPS's root script run for real (bash, sqlite3, runuser, jq) with a
// stub Docker under a test prefix: snapshot, the one-shot arm, and every
// hand-back refusal and rollback (decision 427). Needs root (runuser and
// chown to nobody); skipped elsewhere.
type vpsBox struct {
	t    *testing.T
	root string
}

const dockerStub = `#!/bin/bash
R="$HARDYOS_STANDBY_TEST_ROOT"
echo "$*" >> "$R/docker.log"
case "$1" in
  ps) case "$*" in *label=com.docker.compose.project=netbird*) echo netbird-traefik ;; esac ;;
  stop) echo false > "$R/running" ;;
  start) if [ -e "$R/fail-start" ]; then echo false > "$R/running"; else echo true > "$R/running"; fi ;;
  image) case "$*" in *image.version*) echo 0.83.1 ;; esac ;;
  inspect)
    fmt="$3"; name="$4"
    case "$fmt" in
      *'"/var/lib/netbird"'*) echo "$R/data" ;;
      *'"/etc/netbird/config.yaml"'*) echo "$R/cfg/config.yaml" ;;
      *'"/letsencrypt"'*) echo "$R/le" ;;
      '{{.Image}}') echo sha256:img ;;
      '{{.Config.Image}}') if [ "$name" = netbird-traefik ]; then echo traefik:v3.7.18; else echo netbirdio/netbird-server:0.83.1; fi ;;
      '{{.State.Running}}') cat "$R/running" 2>/dev/null || echo true ;;
      '{{.RestartCount}}') echo 0 ;;
      *) echo "" ;;
    esac ;;
esac
exit 0
`

func newVPSBox(t *testing.T) *vpsBox {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root (runuser, chown to nobody)")
	}
	for _, c := range []string{"bash", "sqlite3", "runuser", "jq", "tar", "sha256sum", "od", "comm", "awk", "cmp"} {
		if _, err := exec.LookPath(c); err != nil {
			t.Skipf("%s isn't installed", c)
		}
	}
	// /tmp-based: the script's work folder for nobody is in /tmp too.
	r, err := os.MkdirTemp("", "vpsbox")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(r) })
	b := &vpsBox{t: t, root: r}
	_, pub, _ := NewKey()
	s, err := Script(ScriptSetup{Hostname: testHost, PublicKey: pub})
	if err != nil {
		t.Fatal(err)
	}
	i := strings.Index(s, "<<'ROOT'\n")
	j := strings.Index(s, "\nROOT\n")
	for _, d := range []string{"bin", "etc/hardyos-standby", "data", "cfg", "le"} {
		os.MkdirAll(filepath.Join(r, d), 0o755)
	}
	os.WriteFile(filepath.Join(r, "root.sh"), []byte(s[i+len("<<'ROOT'\n"):j]), 0o700)
	os.WriteFile(filepath.Join(r, "bin", "docker"), []byte(dockerStub), 0o755)
	os.WriteFile(filepath.Join(r, "bin", "sleep"), []byte("#!/bin/sh\nexit 0\n"), 0o755)
	os.WriteFile(filepath.Join(r, "bin", "logger"), []byte("#!/bin/sh\nexit 0\n"), 0o755)
	os.WriteFile(filepath.Join(r, "etc/hardyos-standby/standby.conf"), []byte("SERVER=netbird-server\nPROJECT=netbird\nHOSTNAME_NB="+testHost+"\nHANDBACK=1\nCHECK_USER=nobody\n"), 0o600)
	os.WriteFile(filepath.Join(r, "cfg/config.yaml"), []byte(testConfig), 0o600)
	os.WriteFile(filepath.Join(r, "running"), []byte("true\n"), 0o644)
	// acme.json with this name's certificate, another one and the account.
	acme := testACME(t, testHost, time.Date(2027, 2, 1, 0, 0, 0, 0, time.UTC))
	var store map[string]map[string]any
	json.Unmarshal(acme, &store)
	store["letsencrypt"]["Certificates"] = append(store["letsencrypt"]["Certificates"].([]any),
		map[string]any{"domain": map[string]any{"main": "other.example.net"}, "certificate": "x", "key": "OTHERKEY"})
	acme, _ = json.Marshal(store)
	os.WriteFile(filepath.Join(r, "le/acme.json"), acme, 0o600)
	b.sql(filepath.Join(r, "data/store.db"), `CREATE TABLE accounts(id TEXT);
		CREATE TABLE users(id TEXT, account_id TEXT, role TEXT, blocked NUMERIC, is_service_user NUMERIC);
		CREATE TABLE personal_access_tokens(id TEXT, user_id TEXT, name TEXT, hashed_token TEXT);
		CREATE TABLE setup_keys(id TEXT); CREATE TABLE policies(id TEXT); CREATE TABLE routes(id TEXT); CREATE TABLE peers(id TEXT);
		INSERT INTO accounts VALUES('acc1'); INSERT INTO users VALUES('u1','acc1','owner',0,0);
		INSERT INTO users VALUES('u3','acc1','user',0,0); INSERT INTO users VALUES('u5','acc1','admin',1,0);
		INSERT INTO personal_access_tokens VALUES('t0','u3','ci','h0');
		INSERT INTO setup_keys VALUES('k1'); INSERT INTO peers VALUES('p1');`)
	// The embedded IdP's (Dex's) sign-in tables.
	b.sql(filepath.Join(r, "data/idp.db"), `CREATE TABLE password(email TEXT PRIMARY KEY, hash BLOB, username TEXT, user_id TEXT);
		CREATE TABLE keys(id TEXT PRIMARY KEY, signing_key BLOB); CREATE TABLE connector(id TEXT PRIMARY KEY, config BLOB);
		CREATE TABLE client(id TEXT PRIMARY KEY, secret TEXT); CREATE TABLE auth_code(id TEXT PRIMARY KEY);
		INSERT INTO password VALUES('owner@example.net', x'2432', 'owner', 'u1'); INSERT INTO keys VALUES('keys', x'00');`)
	return b
}

func (b *vpsBox) sql(db, q string) string {
	b.t.Helper()
	out, err := exec.Command("sqlite3", db, q).CombinedOutput()
	if err != nil {
		b.t.Fatalf("sqlite3: %v %s", err, out)
	}
	return strings.TrimSpace(string(out))
}

func (b *vpsBox) run(stdin []byte, env []string, args ...string) (string, string, error) {
	b.t.Helper()
	c := exec.Command("bash", append([]string{filepath.Join(b.root, "root.sh")}, args...)...)
	c.Env = append([]string{"HARDYOS_STANDBY_TEST_ROOT=" + b.root, "PATH=/usr/bin:/bin"}, env...)
	if stdin != nil {
		c.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	c.Stdout, c.Stderr = &out, &errb
	err := c.Run()
	return out.String(), errb.String(), err
}

// upload builds a hand-back from a copy of the VPS's store changed by q.
func (b *vpsBox) upload(gen, version, q string) []byte {
	b.t.Helper()
	return b.uploadDBs(gen, version, map[string]string{"store": q})
}

// uploadDBs builds a hand-back of the databases named (store, idp,
// events): copies of the VPS's (empty when it has none) changed by their q.
func (b *vpsBox) uploadDBs(gen, version string, dbs map[string]string) []byte {
	b.t.Helper()
	dir := b.t.TempDir()
	os.MkdirAll(filepath.Join(dir, "data"), 0o700)
	for db, q := range dbs {
		dst := filepath.Join(dir, "data", db+".db")
		if src, err := os.ReadFile(filepath.Join(b.root, "data", db+".db")); err == nil {
			os.WriteFile(dst, src, 0o600)
		}
		if q == "" {
			q = "PRAGMA user_version;"
		}
		b.sql(dst, q)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		b.t.Fatal(err)
	}
	defer root.Close()
	sums, err := restoreSums(root)
	if err != nil {
		b.t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := writeRestoreTar(&buf, root, sums, map[string]string{"GENERATION": gen + "\n", "VERSION": version + "\n"}); err != nil {
		b.t.Fatal(err)
	}
	return buf.Bytes()
}

func (b *vpsBox) arm(extra ...string) {
	b.t.Helper()
	if out, errs, err := b.run(nil, nil, append([]string{"arm-restore", "2h"}, extra...)...); err != nil {
		b.t.Fatalf("arm: %v %s %s", err, out, errs)
	}
}

func (b *vpsBox) count(table string) string {
	return b.sql(filepath.Join(b.root, "data/store.db"), "SELECT count(*) FROM "+table)
}

func TestVPSRootScript(t *testing.T) {
	b := newVPSBox(t)
	// Status: hand-back installed, not armed, not fenced.
	out, errs, err := b.run(nil, nil, "status")
	if err != nil {
		t.Fatalf("%v %s", err, errs)
	}
	var vs VPSStatus
	if err := json.Unmarshal([]byte(out), &vs); err != nil || !vs.Running || !vs.HandbackInstalled || vs.RestoreAllowed || vs.Fenced || vs.Version != "0.83.1" {
		t.Fatalf("%v %s", err, out)
	}
	// Snapshot: passes HardyOS's checks; only this name's certificate,
	// never the account; a generation recorded.
	snap, errs, err := b.run(nil, nil, "snapshot")
	if err != nil {
		t.Fatalf("%v %s", err, errs)
	}
	info, err := Check(strings.NewReader(snap), testHost, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !generationRE.MatchString(info.Generation) || info.Peers != 1 || info.SetupKeys != 1 || info.CertNotAfter.IsZero() {
		t.Fatalf("%+v", info)
	}
	files := readTar(t, []byte(snap))
	if bytes.Contains(files[EntryACME], []byte("Account")) || bytes.Contains(files[EntryACME], []byte("OTHERKEY")) {
		t.Fatalf("acme.json not filtered: %s", files[EntryACME])
	}
	gen := info.Generation

	// Restore needs the arm, made by a person (not HardyOS's key), once.
	up := b.upload(gen, StandbyVersion, "INSERT INTO setup_keys VALUES('k2');")
	if _, errs, err := b.run(up, nil, "restore"); err == nil || !strings.Contains(errs, "isn't armed") {
		t.Fatalf("unarmed restore: %v %s", err, errs)
	}
	if _, _, err := b.run(nil, []string{"SUDO_USER=hardyos-standby"}, "arm-restore", "2h"); err == nil {
		t.Fatal("HardyOS's key armed the hand-back")
	}
	if _, _, err := b.run(nil, nil, "arm-restore", "99h"); err == nil {
		t.Fatal("armed for 99 hours")
	}
	b.arm()
	out, _, _ = b.run(nil, nil, "status")
	json.Unmarshal([]byte(out), &vs)
	if !vs.RestoreAllowed || vs.RestoreArmedUntil == "" {
		t.Fatalf("%s", out)
	}
	out, errs, err = b.run(up, nil, "restore")
	if err != nil {
		t.Fatalf("restore: %v %s", err, errs)
	}
	if !strings.Contains(out, "setup_keys:+1") || !strings.Contains(out, "restored") || b.count("setup_keys") != "2" {
		t.Fatalf("%s / %s", out, b.count("setup_keys"))
	}
	if _, err := os.Stat(filepath.Join(b.root, "etc/hardyos-standby/restore-armed")); err == nil {
		t.Fatal("the arm wasn't used up")
	}
	if _, errs, err := b.run(up, nil, "restore"); err == nil || !strings.Contains(errs, "isn't armed") {
		t.Fatalf("second restore on one arm: %v %s", err, errs)
	}

	refused := func(what, gen, version, q, want string, extra ...string) {
		t.Helper()
		before := b.count("setup_keys")
		b.arm(extra...)
		_, errs, err := b.run(b.upload(gen, version, q), nil, "restore")
		if err == nil || !strings.Contains(errs, want) {
			t.Fatalf("%s: %v %q", what, err, errs)
		}
		if b.count("setup_keys") != before {
			t.Fatalf("%s changed the VPS's store", what)
		}
	}
	refused("unknown generation", strings.Repeat("a", 32), StandbyVersion, "", "doesn't come from a snapshot")
	refused("newer standby", gen, "9.0.0", "", "older than the standby")
	refused("other account", gen, StandbyVersion, "UPDATE accounts SET id='evil';", "other NetBird accounts")
	refused("new admin", gen, StandbyVersion, "INSERT INTO users VALUES('u2','acc1','admin',0,0); INSERT INTO setup_keys VALUES('k9');", "owner/admin")
	refused("new token", gen, StandbyVersion, "INSERT INTO personal_access_tokens VALUES('t1','u3','x','h1');", "access tokens")
	// Row contents, not only ids (security review N3).
	refused("promoted user", gen, StandbyVersion, "UPDATE users SET role='admin' WHERE id='u3';", "owner/admin")
	refused("promoted user, odd case", gen, StandbyVersion, "UPDATE users SET role='Owner' WHERE id='u3';", "owner/admin")
	refused("unblocked admin", gen, StandbyVersion, "UPDATE users SET blocked=0 WHERE id='u5';", "owner/admin")
	refused("service user flag", gen, StandbyVersion, "UPDATE users SET is_service_user=1 WHERE id='u1';", "owner/admin")
	refused("new plain admin-named user", gen, StandbyVersion, "INSERT INTO users VALUES('u6','acc1','network_admin',0,0);", "owner/admin")
	refused("token moved to the owner", gen, StandbyVersion, "UPDATE personal_access_tokens SET user_id='u1' WHERE id='t0';", "access tokens")
	refused("token rehashed", gen, StandbyVersion, "UPDATE personal_access_tokens SET hashed_token='evil' WHERE id='t0';", "access tokens")
	refused("table renamed (case)", gen, StandbyVersion,
		"ALTER TABLE personal_access_tokens RENAME TO pat_tmp; ALTER TABLE pat_tmp RENAME TO Personal_Access_Tokens; INSERT INTO Personal_Access_Tokens VALUES('t9','u1','x','h9');", "access tokens")
	refused("table renamed away", gen, StandbyVersion,
		"ALTER TABLE personal_access_tokens RENAME TO pat_old; CREATE VIEW personal_access_tokens AS SELECT * FROM pat_old WHERE 0;", "no table personal_access_tokens")
	refused("column missing", gen, StandbyVersion, "ALTER TABLE users DROP COLUMN blocked;", "no column blocked")
	refused("broken schema query", gen, StandbyVersion, "ALTER TABLE users RENAME COLUMN role TO role2; ALTER TABLE users ADD COLUMN ROLE2X TEXT;", "no column role")
	for _, q := range []string{
		"UPDATE password SET hash=x'00' WHERE email='owner@example.net';",
		"INSERT INTO password VALUES('evil@example.net', x'00', 'evil', 'u3');",
		"UPDATE keys SET signing_key=x'ff';",
		"INSERT INTO connector VALUES('evil', x'00');",
		"INSERT INTO client VALUES('evil', 's');",
		"DROP TABLE password; CREATE TABLE Password(email TEXT, hash BLOB, username TEXT, user_id TEXT);",
	} {
		before := b.count("setup_keys")
		b.arm()
		_, errs, err := b.run(b.uploadDBs(gen, StandbyVersion, map[string]string{"store": "", "idp": q}), nil, "restore")
		if err == nil || !strings.Contains(errs, "sign-in tables") {
			t.Fatalf("idp.db %q: %v %q", q, err, errs)
		}
		if b.count("setup_keys") != before {
			t.Fatal("changed the VPS's store")
		}
	}
	// Unchanged sign-in tables and a new plain user pass; the IdP's other
	// tables (codes, sessions) may change.
	b.arm()
	if _, errs, err := b.run(b.uploadDBs(gen, StandbyVersion, map[string]string{
		"store": "INSERT INTO users VALUES('u4','acc1','user',0,0); DELETE FROM personal_access_tokens;",
		"idp":   "INSERT INTO auth_code VALUES('c1');"}), nil, "restore"); err != nil {
		t.Fatalf("plain changes: %v %s", err, errs)
	}
	// Allowed by the person on the VPS.
	b.arm("--allow-new-admins")
	if _, errs, err := b.run(b.uploadDBs(gen, StandbyVersion, map[string]string{
		"store": "INSERT INTO users VALUES('u2','acc1','admin',0,0);",
		"idp":   "UPDATE keys SET signing_key=x'01';"}), nil, "restore"); err != nil {
		t.Fatalf("allowed admin: %v %s", err, errs)
	}
	// A server that doesn't stay up is rolled back to the VPS's own copy.
	before := b.count("setup_keys")
	os.WriteFile(filepath.Join(b.root, "fail-start"), nil, 0o644)
	refused("server down after swap", gen, StandbyVersion, "INSERT INTO setup_keys VALUES('k7');", "didn't stay up")
	if b.count("setup_keys") != before {
		t.Fatal("not rolled back")
	}
	// The rollback puts back what the VPS had: a database the upload added
	// goes, and a fenced VPS's server stays stopped (review L-a).
	events := filepath.Join(b.root, "data/events.db")
	os.Remove(events)
	if _, errs, err := b.run(nil, nil, "fence"); err != nil {
		t.Fatalf("%v %s", err, errs)
	}
	os.WriteFile(filepath.Join(b.root, "docker.log"), nil, 0o644)
	b.arm()
	if _, errs, err := b.run(b.uploadDBs(gen, StandbyVersion, map[string]string{"store": "", "events": "CREATE TABLE e(id TEXT);"}), nil, "restore"); err == nil || !strings.Contains(errs, "stays stopped") {
		t.Fatalf("fenced rollback: %v %s", err, errs)
	}
	if _, err := os.Stat(events); err == nil {
		t.Fatal("the upload's events.db stayed")
	}
	logb, _ := os.ReadFile(filepath.Join(b.root, "docker.log"))
	var last string
	for _, l := range strings.Split(string(logb), "\n") {
		if strings.HasPrefix(l, "start ") || strings.HasPrefix(l, "stop ") {
			last = l
		}
	}
	if !strings.HasPrefix(last, "stop ") {
		t.Fatalf("fenced server started again by the rollback:\n%s", logb)
	}
	if _, err := os.Stat(filepath.Join(b.root, "etc/hardyos-standby/fenced")); err != nil {
		t.Fatal("the fence went with the rollback")
	}
	os.Remove(filepath.Join(b.root, "fail-start"))
	if _, _, err := b.run(nil, nil, "unfence"); err != nil {
		t.Fatal(err)
	}
	// Fence and unfence.
	if _, errs, err := b.run(nil, nil, "fence"); err != nil {
		t.Fatalf("%v %s", err, errs)
	}
	out, _, _ = b.run(nil, nil, "status")
	json.Unmarshal([]byte(out), &vs)
	if !vs.Fenced || vs.Running || vs.FencedUntil == "" {
		t.Fatalf("%s", out)
	}
	if until, err := time.Parse(time.RFC3339, vs.FencedUntil); err != nil || until.Sub(time.Now()) > 2*time.Hour+time.Minute || until.Sub(time.Now()) < 110*time.Minute {
		t.Fatalf("fenced until %s", vs.FencedUntil)
	}
	// Not expired: fence-expire leaves it; HardyOS's key can't run it.
	if _, _, err := b.run(nil, nil, "fence-expire"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.run(nil, []string{"SUDO_USER=hardyos-standby"}, "fence-expire"); err == nil {
		t.Fatal("HardyOS's key ran fence-expire")
	}
	out, _, _ = b.run(nil, nil, "status")
	json.Unmarshal([]byte(out), &vs)
	if !vs.Fenced || vs.Running {
		t.Fatalf("%s", out)
	}
	snap, _, _ = b.run(nil, nil, "snapshot")
	if _, err := Check(strings.NewReader(snap), testHost, nil); err == nil || !strings.Contains(err.Error(), "fenced") {
		t.Fatalf("fenced snapshot: %v", err)
	}
	// Expired (HardyOS didn't renew it): the timer starts the server.
	fenceFile := filepath.Join(b.root, "etc/hardyos-standby/fenced")
	os.WriteFile(fenceFile, []byte(strconv.FormatInt(time.Now().Add(-time.Minute).Unix(), 10)+"\n"), 0o600)
	out, _, _ = b.run(nil, nil, "status")
	json.Unmarshal([]byte(out), &vs)
	if vs.Fenced {
		t.Fatalf("expired fence shown: %s", out)
	}
	if out, errs, err := b.run(nil, nil, "fence-expire"); err != nil || !strings.Contains(out, "expired") {
		t.Fatalf("%v %s %s", err, out, errs)
	}
	if _, err := os.Stat(fenceFile); err == nil {
		t.Fatal("expired fence kept")
	}
	out, _, _ = b.run(nil, nil, "status")
	json.Unmarshal([]byte(out), &vs)
	if !vs.Running {
		t.Fatalf("not started: %s", out)
	}
	// Only the newest five backups are kept.
	entries, _ := os.ReadDir(filepath.Join(b.root, "var/lib/hardyos-standby/root"))
	n := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "before-handback-") {
			n++
		}
	}
	if n > 5 {
		t.Fatalf("%d backups kept", n)
	}
	_ = io.Discard
}
