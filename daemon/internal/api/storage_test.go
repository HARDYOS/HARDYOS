package api

import (
	"context"
	"io/fs"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/events"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/metrics"
	"github.com/hardyos/hardyos/daemon/internal/notify"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/storage"
	"github.com/hardyos/hardyos/daemon/internal/store"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

const apiLsblk = `{"blockdevices":[
 {"name":"sda","path":"/dev/sda","size":4000000000000,"type":"disk","rota":true,"tran":"sata","mountpoints":[null]},
 {"name":"sdb","path":"/dev/sdb","size":4000000000000,"type":"disk","rota":true,"tran":"sata","mountpoints":[null]},
 {"name":"sdc","path":"/dev/sdc","size":4000000000000,"type":"disk","rota":true,"tran":"sata","mountpoints":[null],
  "children":[{"name":"sdc1","size":4000000000000,"type":"part","fstype":"zfs_member","label":"other","mountpoints":[null]}]},
 {"name":"nvme0n1","path":"/dev/nvme0n1","size":256000000000,"type":"disk","rota":false,"tran":"nvme","mountpoints":[null],
  "children":[{"name":"nvme0n1p1","size":256000000000,"type":"part","fstype":"ext4","mountpoints":["/"]}]}
]}`

func newStorageEnv(t *testing.T) (*testEnv, *sysexec.Fake) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "api.db"))
	if err != nil {
		t.Fatal(err)
	}
	broker := events.NewBroker()

	root := fstest.MapFS{"proc/meminfo": {Data: []byte("MemTotal: 16777216 kB\n")}}
	for _, n := range []string{"sda", "sdb", "sdc", "nvme0n1"} {
		root["dev/disk/by-id/ata-DISK_"+n] = &fstest.MapFile{Data: []byte("../../" + n), Mode: fs.ModeSymlink | 0o777}
	}
	fake := (&sysexec.Fake{}).
		On("lsblk -J -b -o NAME,PATH,SIZE,TYPE,ROTA,MODEL,SERIAL,WWN,TRAN,FSTYPE,LABEL,MOUNTPOINTS,HOTPLUG,PHY-SEC", apiLsblk).
		OnPrefix("zpool labelclear", sysexec.Result{}).
		OnPrefix("wipefs", sysexec.Result{}).
		OnPrefix("zpool create", sysexec.Result{}).
		OnPrefix("zfs create", sysexec.Result{}).
		OnPrefix("zfs list", sysexec.Result{}).
		On("zpool status -P -p tank", "  pool: tank\n state: ONLINE\nconfig:\n\n\tNAME STATE READ WRITE CKSUM\n\ttank ONLINE 0 0 0\n\nerrors: No known data errors\n").
		On("zpool list -Hp -o name,size,allocated,free,fragmentation,capacity,health,guid", "")

	sock := filepath.Join(t.TempDir(), "priv.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	ps := &priv.Server{AllowedUIDs: []uint32{uint32(os.Getuid())}}
	priv.RegisterBuiltins(ps)
	priv.RegisterStorage(ps, priv.StorageEnv{Runner: fake, Root: root, KeyDir: filepath.Join(dir, "keys"),
		ARCConf: filepath.Join(dir, "zfs.conf"), ARCParam: filepath.Join(dir, "arc")})
	go func() { _ = ps.Serve(ctx, ln) }()
	pc := priv.NewClient(sock)

	m := &jobs.Manager{DB: db, Events: broker}
	nc := &notify.Center{DB: db, Events: broker}
	svc := &storage.Service{Priv: pc, Jobs: m, DB: db, Notify: nc, Monitor: time.Millisecond}
	RegisterJobKinds(m, pc)
	svc.RegisterJobs(m)
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(New(Config{DB: db, Jobs: m, Events: broker, Priv: pc, Storage: svc, Notify: nc, Insecure: true}))
	t.Cleanup(func() {
		srv.Close()
		cancel()
		m.Wait()
		db.Close()
	})
	return &testEnv{srv: srv, db: db, broker: broker}, fake
}

func waitJob(t *testing.T, c *client, id string) map[string]any {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		var j map[string]any
		c.do("GET", "/api/v1/jobs/"+id, nil, &j)
		switch j["state"] {
		case "succeeded", "failed", "cancelled":
			return j
		}
	}
	t.Fatalf("job %s didn't finish", id)
	return nil
}

func TestStorageAPI(t *testing.T) {
	env, fake := newStorageEnv(t)
	admin := env.client(t)
	admin.do("POST", "/api/v1/setup/admin", map[string]string{"username": "cade", "password": "supersecret1"}, nil)

	var hwResp struct {
		Disks []struct {
			Name  string `json:"name"`
			Usage string `json:"usage"`
		} `json:"disks"`
		Capabilities map[string]any `json:"capabilities"`
	}
	if code := admin.do("GET", "/api/v1/hardware", nil, &hwResp); code != 200 || len(hwResp.Disks) != 4 {
		t.Fatalf("hardware = %d %+v", code, hwResp)
	}

	var rec struct {
		Spec struct {
			Name string `json:"name"`
			Data []struct {
				Type  string   `json:"type"`
				Disks []string `json:"disks"`
			} `json:"data"`
		} `json:"spec"`
	}
	if code := admin.do("GET", "/api/v1/storage/recommendation?name=tank", nil, &rec); code != 200 {
		t.Fatalf("recommendation = %d", code)
	}
	if rec.Spec.Data[0].Type != "mirror" || len(rec.Spec.Data[0].Disks) != 2 {
		t.Fatalf("recommendation = %+v (the in-use sdc must be left out)", rec)
	}

	body := map[string]any{"spec": rec.Spec}
	if code := admin.do("POST", "/api/v1/storage/pools", body, nil); code != 400 {
		t.Fatalf("create without confirmWipe = %d, want 400", code)
	}
	body["confirmWipe"] = true
	var accepted struct {
		Job struct {
			ID string `json:"id"`
		} `json:"job"`
	}
	if code := admin.do("POST", "/api/v1/storage/pools", body, &accepted); code != 202 {
		t.Fatalf("create = %d", code)
	}
	j := waitJob(t, admin, accepted.Job.ID)
	if j["state"] != "succeeded" {
		t.Fatalf("create job = %+v", j)
	}
	if !strings.Contains(strings.Join(fake.Lines(), "\n"), "zpool create -f -o ashift=12") {
		t.Fatal("zpool create never ran")
	}

	// A disk that belongs to another pool is refused by the root helper; the job fails with its reason.
	bad := map[string]any{"confirmWipe": true, "spec": map[string]any{"name": "tank2", "data": []map[string]any{
		{"type": "mirror", "disks": []string{"/dev/disk/by-id/ata-DISK_sda", "/dev/disk/by-id/ata-DISK_sdc"}}}}}
	if code := admin.do("POST", "/api/v1/storage/pools", bad, &accepted); code != 202 {
		t.Fatalf("create bad = %d", code)
	}
	if j := waitJob(t, admin, accepted.Job.ID); j["state"] != "failed" || !strings.Contains(j["error"].(string), "member of pool other") {
		t.Fatalf("bad create job = %+v", j)
	}

	// Destroy needs the exact name; boot pool is refused.
	if code := admin.do("DELETE", "/api/v1/storage/pools/tank", map[string]string{"confirmName": "TANK"}, nil); code != 400 {
		t.Fatalf("destroy without exact name = %d", code)
	}
	if code := admin.do("POST", "/api/v1/storage/pools/rpool/scrub", map[string]string{"action": "start"}, nil); code != 409 {
		t.Fatalf("scrub boot pool = %d, want 409", code)
	}

	// Policies.
	var pols []map[string]any
	admin.do("GET", "/api/v1/storage/snapshot-policies", nil, &pols)
	if len(pols) != 4 {
		t.Fatalf("default policies = %d", len(pols))
	}
	if code := admin.do("POST", "/api/v1/storage/snapshot-policies", map[string]any{"dataset": "tank/apps", "frequency": "yearly", "keep": 3}, nil); code != 400 {
		t.Fatalf("bad policy = %d", code)
	}

	// Notifications: the pool-ready message is waiting.
	var notes []map[string]any
	admin.do("GET", "/api/v1/notifications", nil, &notes)
	if len(notes) == 0 || !strings.Contains(notes[0]["title"].(string), "tank is ready") {
		t.Fatalf("notifications = %+v", notes)
	}
	if code := admin.do("POST", "/api/v1/notifications/read-all", nil, nil); code != 204 {
		t.Fatalf("read-all = %d", code)
	}

	// Regular users can't touch storage.
	admin.do("POST", "/api/v1/users", map[string]string{"username": "kid", "password": "kidpassword1"}, nil)
	kid := env.client(t)
	kid.do("POST", "/api/v1/auth/login", map[string]string{"username": "kid", "password": "kidpassword1"}, nil)
	if code := kid.do("GET", "/api/v1/storage/pools", nil, nil); code != 403 {
		t.Fatalf("kid pools = %d", code)
	}
	var kidNotes []map[string]any
	kid.do("GET", "/api/v1/notifications", nil, &kidNotes)
	if len(kidNotes) != 0 {
		t.Fatalf("kid sees admin notifications: %+v", kidNotes)
	}

	var entries []map[string]any
	admin.do("GET", "/api/v1/audit?action=storage.", nil, &entries)
	if len(entries) < 3 {
		t.Fatalf("audit entries = %d", len(entries))
	}
}

func TestSystemInfoAndMetrics(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	root := fstest.MapFS{
		"etc/os-release":            {Data: []byte("NAME=\"Debian GNU/Linux\"\nPRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\n")},
		"proc/sys/kernel/osrelease": {Data: []byte("6.12.48-amd64\n")},
		"proc/uptime":               {Data: []byte("3600.25 10\n")},
		"proc/meminfo":              {Data: []byte("MemTotal: 8000000 kB\nMemAvailable: 4000000 kB\n")},
	}
	col := &metrics.Collector{Root: root}
	srv := httptest.NewServer(New(Config{DB: db, Root: root, Metrics: col, Insecure: true}))
	defer srv.Close()
	env := &testEnv{srv: srv, db: db}
	c := env.client(t)
	c.do("POST", "/api/v1/setup/admin", map[string]string{"username": "cade", "password": "supersecret1"}, nil)

	var info SystemInfo
	if code := c.do("GET", "/api/v1/system/info", nil, &info); code != 200 {
		t.Fatalf("info = %d", code)
	}
	if info.OS != "Debian GNU/Linux 13 (trixie)" || info.Kernel != "6.12.48-amd64" || info.UptimeSecs != 3600.25 {
		t.Fatalf("info = %+v", info)
	}
	var snap metrics.Snapshot
	if code := c.do("GET", "/api/v1/system/metrics", nil, &snap); code != 200 {
		t.Fatalf("metrics = %d", code)
	}
	anon := env.client(t)
	if code := anon.do("GET", "/api/v1/system/metrics", nil, nil); code != 401 {
		t.Fatalf("anonymous metrics = %d", code)
	}
}
