package api

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/hardyos/hardyos/daemon/internal/events"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/notify"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/store"
	"github.com/hardyos/hardyos/daemon/internal/updates"
	"github.com/hardyos/hardyos/daemon/internal/vms"
)

// stubVMs is a root helper that pretends to run VMs.
type stubVMs struct {
	mu     sync.Mutex
	vms    map[string]*vms.VM
	calls  []string
	bridge string
	tokens map[string]string
	vnc    string // socket of the fake VNC server
}

func (d *stubVMs) rec(op string, raw json.RawMessage) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls = append(d.calls, op+" "+string(raw))
}

func (d *stubVMs) called(prefix string) []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []string
	for _, c := range d.calls {
		if strings.HasPrefix(c, prefix) {
			out = append(out, c)
		}
	}
	return out
}

func (d *stubVMs) register(ps *priv.Server) {
	h := func(op string, fn func(raw json.RawMessage) (any, error)) {
		ps.Handle(op, func(_ context.Context, raw json.RawMessage) (any, error) {
			d.rec(op, raw)
			return fn(raw)
		})
	}
	ref := func(raw json.RawMessage) (*vms.VM, error) {
		var a struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(raw, &a)
		d.mu.Lock()
		defer d.mu.Unlock()
		v, ok := d.vms[a.ID]
		if !ok {
			return nil, priv.Errorf(priv.CodeBadArgs, "there's no virtual machine with that name")
		}
		c := *v
		return &c, nil
	}
	setState := func(raw json.RawMessage, state string) (*vms.VM, error) {
		v, err := ref(raw)
		if err != nil {
			return nil, err
		}
		d.mu.Lock()
		d.vms[v.ID].State = state
		d.mu.Unlock()
		v.State = state
		return v, nil
	}
	h(priv.OpVMsList, func(json.RawMessage) (any, error) {
		d.mu.Lock()
		defer d.mu.Unlock()
		o := vms.Overview{VMs: []vms.VM{}, Kept: []vms.KeptDisk{}}
		for _, v := range d.vms {
			o.VMs = append(o.VMs, *v)
		}
		return o, nil
	})
	h(priv.OpVMsGet, func(raw json.RawMessage) (any, error) { return ref(raw) })
	h(priv.OpVMsCapabilities, func(json.RawMessage) (any, error) {
		d.mu.Lock()
		defer d.mu.Unlock()
		return vms.Capabilities{Supported: true, Bridge: d.bridge, Pools: []string{"tank"}}, nil
	})
	h(priv.OpVMsBridge, func(json.RawMessage) (any, error) {
		d.mu.Lock()
		defer d.mu.Unlock()
		d.bridge = "br0"
		return priv.VMBridgeResult{Bridge: "br0"}, nil
	})
	h(priv.OpVMsISOVirtio, func(json.RawMessage) (any, error) {
		return priv.VMTaskResult{Task: &vms.Task{ID: "t-virtio", File: vms.VirtioFile}}, nil
	})
	h(priv.OpVMsISODownload, func(raw json.RawMessage) (any, error) {
		return priv.VMTaskResult{Task: &vms.Task{ID: "t-dl", File: "noble.img"}}, nil
	})
	h(priv.OpVMsTask, func(raw json.RawMessage) (any, error) {
		var a vms.TaskArgs
		_ = json.Unmarshal(raw, &a)
		return priv.VMTaskResult{Task: &vms.Task{ID: a.ID, Done: true, Progress: 100, Message: "Done"}}, nil
	})
	h(priv.OpVMsCreate, func(raw json.RawMessage) (any, error) {
		var a vms.CreateArgs
		_ = json.Unmarshal(raw, &a)
		v := &vms.VM{Spec: a.Spec, State: "stopped", Addresses: []string{}}
		d.mu.Lock()
		d.vms[a.Spec.ID] = v
		d.mu.Unlock()
		return vms.Result{VM: v, Warnings: []string{}}, nil
	})
	h(priv.OpVMsImport, func(json.RawMessage) (any, error) {
		return priv.VMTaskResult{Task: &vms.Task{ID: "t-import"}}, nil
	})
	h(priv.OpVMsStart, func(raw json.RawMessage) (any, error) {
		v, err := setState(raw, "running")
		return vms.Result{VM: v, Warnings: []string{}}, err
	})
	h(priv.OpVMsStop, func(raw json.RawMessage) (any, error) { return setState(raw, "stopped") })
	h(priv.OpVMsRestart, func(raw json.RawMessage) (any, error) {
		v, err := ref(raw)
		return vms.Result{VM: v, Warnings: []string{}}, err
	})
	h(priv.OpVMsUpdate, func(raw json.RawMessage) (any, error) {
		var a vms.UpdateArgs
		_ = json.Unmarshal(raw, &a)
		v := &vms.VM{Spec: a.Spec, State: "stopped"}
		return vms.Result{VM: v, Warnings: []string{}}, nil
	})
	h(priv.OpVMsDelete, func(raw json.RawMessage) (any, error) {
		var a vms.DeleteArgs
		_ = json.Unmarshal(raw, &a)
		d.mu.Lock()
		delete(d.vms, a.ID)
		d.mu.Unlock()
		return map[string]bool{"ok": true}, nil
	})
	h(priv.OpVMsSnapshot, func(json.RawMessage) (any, error) {
		return vms.Snapshot{Name: "vm-20261026-120000", Consistent: false}, nil
	})
	h(priv.OpVMsSnapshots, func(json.RawMessage) (any, error) {
		return priv.VMSnapshotsResult{Snapshots: []vms.Snapshot{{Name: "vm-20261026-120000", Label: "before"}}}, nil
	})
	h(priv.OpVMsRollback, func(raw json.RawMessage) (any, error) { return ref(raw) })
	h(priv.OpVMsLogs, func(json.RawMessage) (any, error) { return priv.VMLogsResult{Logs: "qemu started"}, nil })
	h(priv.OpVMsConsole, func(raw json.RawMessage) (any, error) {
		v, err := ref(raw)
		if err != nil {
			return nil, err
		}
		if v.State != "running" {
			return nil, priv.Errorf(priv.CodeBadArgs, "start the VM to see its screen")
		}
		tok := strings.Repeat("ab", 32)
		d.mu.Lock()
		d.tokens[tok] = v.ID
		d.mu.Unlock()
		return vms.ConsoleToken{Token: tok, Expires: time.Now().Add(time.Minute)}, nil
	})
	ps.Handle(priv.OpVMsConsoleOpen, func(_ context.Context, raw json.RawMessage) (any, error) {
		var a vms.ConsoleOpenArgs
		_ = json.Unmarshal(raw, &a)
		d.mu.Lock()
		vm, ok := d.tokens[a.Token]
		delete(d.tokens, a.Token)
		d.mu.Unlock()
		if !ok || vm != a.ID {
			return nil, priv.Errorf(priv.CodeBadArgs, "the console link has expired; open the console again")
		}
		c, err := net.Dial("unix", d.vnc)
		if err != nil {
			return nil, err
		}
		f, err := c.(*net.UnixConn).File()
		c.Close()
		return &priv.FileResult{Data: map[string]bool{"ok": true}, File: f}, err
	})
}

func newVMEnv(t *testing.T) (*testEnv, *stubVMs) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(t.TempDir(), "priv.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	stub := &stubVMs{vms: map[string]*vms.VM{}, tokens: map[string]string{}}
	ps := &priv.Server{AllowedUIDs: []uint32{uint32(os.Getuid())}}
	stub.register(ps)
	go func() { _ = ps.Serve(ctx, ln) }()
	pc := priv.NewClient(sock)
	broker := events.NewBroker()
	m := &jobs.Manager{DB: db, Events: broker}
	RegisterJobKinds(m, pc)
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	upd := &updates.Service{Priv: pc, Jobs: m, DB: db, Dir: t.TempDir(), Notify: &notify.Center{DB: db, Events: broker}}
	srv := httptest.NewServer(New(Config{DB: db, Jobs: m, Events: broker, Priv: pc, Updates: upd, Insecure: true}))
	t.Cleanup(func() {
		srv.Close()
		cancel()
		m.Wait()
		db.Close()
	})
	return &testEnv{srv: srv, db: db, broker: broker}, stub
}

func linuxRequest() VMCreateRequest {
	return VMCreateRequest{
		Spec: vms.Spec{ID: "web", Name: "Web server", Template: "linux", OS: "linux", Pool: "tank",
			CPU: vms.CPU{Cores: 2}, Memory: vms.Memory{MB: 4096},
			Disks: []vms.Disk{{Name: "disk0", SizeGB: 32, Import: &vms.Import{File: "noble.img"}}},
			Media: []vms.Media{{Kind: vms.MediaCloudInit}},
			NICs:  []vms.NIC{{Mode: vms.NICBridge}}, GuestAgent: true,
			CloudInit: &vms.CloudInit{User: "cade", SSHKeys: []string{}}},
		Password:  "correct horse battery",
		Start:     true,
		Downloads: []vms.DownloadArgs{{URL: "https://cloud-images.ubuntu.com/noble/current/noble.img"}},
	}
}

func TestVMsAPI(t *testing.T) {
	env, stub := newVMEnv(t)
	admin := env.client(t)
	admin.do("POST", "/api/v1/setup/admin", map[string]string{"username": "cade", "password": "supersecret1"}, nil)
	admin.do("POST", "/api/v1/users", map[string]string{"username": "kid", "password": "kidpassword1"}, nil)
	kid := env.client(t)
	kid.do("POST", "/api/v1/auth/login", map[string]string{"username": "kid", "password": "kidpassword1"}, nil)

	if code := kid.do("GET", "/api/v1/vms", nil, nil); code != 403 {
		t.Fatalf("a family member listed VMs: %d", code)
	}
	var tmpl []vms.Template
	if code := admin.do("GET", "/api/v1/vms/templates", nil, &tmpl); code != 200 || len(tmpl) < 8 || tmpl[0].ID != "windows11" {
		t.Fatalf("templates = %d %d", code, len(tmpl))
	}

	// A bad spec is answered at once with every problem.
	bad := linuxRequest()
	bad.Spec.ID = "Web Server"
	bad.Spec.CPU.Cores = 0
	var e ErrorResponse
	if code := admin.do("POST", "/api/v1/vms", bad, &e); code != 400 || len(e.Details) < 2 {
		t.Fatalf("bad spec = %d %+v", code, e)
	}

	// Create: download, bridge, create, import, start, in that order.
	var acc struct {
		Job struct {
			ID     string          `json:"id"`
			Params json.RawMessage `json:"params"`
		} `json:"job"`
	}
	if code := admin.do("POST", "/api/v1/vms", linuxRequest(), &acc); code != 202 {
		t.Fatalf("create = %d", code)
	}
	if strings.Contains(string(acc.Job.Params), "correct horse") {
		t.Fatalf("the password is in the job's parameters: %s", acc.Job.Params)
	}
	j := waitJobDone(t, admin, acc.Job.ID)
	if j["state"] != "succeeded" {
		t.Fatalf("create job = %+v", j)
	}
	var order []string
	stub.mu.Lock()
	for _, c := range stub.calls {
		op, _, _ := strings.Cut(c, " ")
		if op != priv.OpVMsTask && op != priv.OpVMsGet && op != priv.OpVMsCapabilities {
			order = append(order, op)
		}
	}
	stub.mu.Unlock()
	if strings.Join(order, ",") != "vms.iso.download,vms.bridge,vms.create,vms.import,vms.start" {
		t.Fatalf("order = %v", order)
	}
	created := stub.called(priv.OpVMsCreate)[0]
	if !strings.Contains(created, `"password":"correct horse battery"`) {
		t.Fatalf("the password didn't reach root: %s", created)
	}
	var dl vms.DownloadArgs
	_, raw, _ := strings.Cut(stub.called(priv.OpVMsISODownload)[0], " ")
	_ = json.Unmarshal([]byte(raw), &dl)
	if dl.Pool != "tank" {
		t.Fatalf("download = %+v", dl)
	}

	var list vms.Overview
	if code := admin.do("GET", "/api/v1/vms", nil, &list); code != 200 || len(list.VMs) != 1 || list.VMs[0].State != "running" {
		t.Fatalf("list = %d %+v", code, list)
	}
	// Deleting a running VM is refused; with the wrong name too.
	if code := admin.do("DELETE", "/api/v1/vms/web", VMDeleteRequest{Confirm: "web"}, nil); code != 409 {
		t.Fatalf("delete running = %d", code)
	}
	if code := admin.do("POST", "/api/v1/vms/web/stop", nil, &acc); code != 202 {
		t.Fatalf("stop = %d", code)
	}
	if j := waitJobDone(t, admin, acc.Job.ID); j["state"] != "succeeded" {
		t.Fatalf("stop job = %+v", j)
	}
	if code := admin.do("POST", "/api/v1/vms/web/explode", nil, nil); code != 404 {
		t.Fatalf("unknown action = %d", code)
	}
	if code := admin.do("POST", "/api/v1/vms/nope/start", nil, nil); code != 404 {
		t.Fatalf("unknown VM = %d", code)
	}
	if code := admin.do("POST", "/api/v1/vms/web/rollback", VMRollbackRequest{Snapshot: "vm-20261026-120000", Confirm: "nope"}, nil); code != 400 {
		t.Fatalf("rollback without the name = %d", code)
	}
	if code := admin.do("POST", "/api/v1/vms/web/rollback", VMRollbackRequest{Snapshot: "vm-20261026-120000", Confirm: "Web server"}, &acc); code != 202 {
		t.Fatalf("rollback = %d", code)
	}
	waitJobDone(t, admin, acc.Job.ID)
	if code := admin.do("POST", "/api/v1/vms/web/snapshots", VMSnapshotRequest{Label: "before"}, &acc); code != 202 {
		t.Fatalf("snapshot = %d", code)
	}
	j = waitJobDone(t, admin, acc.Job.ID)
	if res, _ := j["result"].(map[string]any); res == nil || len(res["warnings"].([]any)) != 1 {
		t.Fatalf("snapshot job = %+v", j)
	}
	if code := admin.do("DELETE", "/api/v1/vms/web", VMDeleteRequest{Confirm: "nope"}, nil); code != 400 {
		t.Fatalf("delete without the name = %d", code)
	}
	if code := admin.do("DELETE", "/api/v1/vms/web", VMDeleteRequest{Confirm: "Web server", KeepDisks: true}, &acc); code != 202 {
		t.Fatalf("delete = %d", code)
	}
	waitJobDone(t, admin, acc.Job.ID)
	if got := stub.called(priv.OpVMsDelete); len(got) != 1 || !strings.Contains(got[0], `"keepDisks":true`) {
		t.Fatalf("delete calls = %v", got)
	}
	if code := admin.do("POST", "/api/v1/vms/isos/download", vms.DownloadArgs{URL: "http://x/y.iso"}, nil); code != 400 {
		t.Fatalf("http download = %d", code)
	}

	// Every change is in the audit log.
	var audit []map[string]any
	admin.do("GET", "/api/v1/audit?action=vms.", nil, &audit)
	got := map[string]bool{}
	for _, a := range audit {
		got[a["action"].(string)] = true
	}
	for _, want := range []string{"vms.create", "vms.stop", "vms.rollback", "vms.snapshot", "vms.delete"} {
		if !got[want] {
			t.Errorf("no audit entry for %s: %v", want, got)
		}
	}
}

func TestVMConsoleRelay(t *testing.T) {
	env, stub := newVMEnv(t)
	// The VM's VNC server: says hello, then echoes upper-cased.
	sock := filepath.Join(t.TempDir(), "vnc.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	stub.vnc = sock
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = c.Write([]byte("RFB 003.008\n"))
				buf := make([]byte, 64)
				n, _ := c.Read(buf)
				_, _ = c.Write([]byte(strings.ToUpper(string(buf[:n]))))
			}()
		}
	}()
	stub.vms["web"] = &vms.VM{Spec: vms.Spec{ID: "web", Name: "Web"}, State: "stopped"}

	admin := env.client(t)
	admin.do("POST", "/api/v1/setup/admin", map[string]string{"username": "cade", "password": "supersecret1"}, nil)
	var e ErrorResponse
	if code := admin.do("POST", "/api/v1/vms/web/console", nil, &e); code != 400 || !strings.Contains(e.Message, "start the VM") {
		t.Fatalf("console of a stopped VM = %d %+v", code, e)
	}
	stub.vms["web"].State = "running"
	var sess VMConsoleSession
	if code := admin.do("POST", "/api/v1/vms/web/console", nil, &sess); code != 200 || sess.Token == "" || !strings.HasPrefix(sess.Path, "/api/v1/vms/web/console/ws?token=") {
		t.Fatalf("console = %d %+v", code, sess)
	}
	ctx := context.Background()
	dial := func(path string) (*websocket.Conn, *http.Response, error) {
		u := "ws" + strings.TrimPrefix(env.srv.URL, "http") + path
		return websocket.Dial(ctx, u, &websocket.DialOptions{HTTPClient: admin.http, HTTPHeader: http.Header{"Origin": {env.srv.URL}}, Subprotocols: []string{"binary"}})
	}
	// Another VM's path with this token, or a made-up token: refused.
	if _, res, err := dial("/api/v1/vms/other/console/ws?token=" + sess.Token); err == nil || res == nil || res.StatusCode != 400 {
		t.Fatalf("token for another VM: %v %v", res, err)
	}
	if code := admin.do("POST", "/api/v1/vms/web/console", nil, &sess); code != 200 {
		t.Fatal(code)
	}
	conn, _, err := dial(sess.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var got strings.Builder
	for !strings.Contains(got.String(), "RFB 003.008") {
		_, b, err := conn.Read(rctx)
		if err != nil {
			t.Fatal(err)
		}
		got.Write(b)
	}
	if err := conn.Write(rctx, websocket.MessageBinary, []byte("hello vm")); err != nil {
		t.Fatal(err)
	}
	got.Reset()
	for !strings.Contains(got.String(), "HELLO VM") {
		_, b, err := conn.Read(rctx)
		if err != nil {
			t.Fatal(err)
		}
		got.Write(b)
	}
	// The token was used up.
	if _, res, err := dial(sess.Path); err == nil || res.StatusCode != 400 {
		t.Fatalf("token reused: %v %v", res, err)
	}
	conn.Close(websocket.StatusNormalClosure, "")
	time.Sleep(100 * time.Millisecond)
	var audit []map[string]any
	admin.do("GET", "/api/v1/audit?action=vms.console", nil, &audit)
	actions := map[string]int{}
	for _, a := range audit {
		actions[a["action"].(string)+"/"+a["outcome"].(string)]++
	}
	if actions["vms.console.open/success"] != 1 || actions["vms.console.open/denied"] != 2 || actions["vms.console.close/success"] != 1 {
		t.Fatalf("audit = %v", actions)
	}
}
