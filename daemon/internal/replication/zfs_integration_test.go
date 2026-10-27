package replication

import (
	"bytes"
	"context"
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/replica"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// itemsOn resolves items on the integration test's source pool.
type itemsOn struct{ pool string }

func (i itemsOn) List(ctx context.Context) ([]replica.LocalItem, error) {
	return []replica.LocalItem{
		{Kind: replica.KindShare, ID: "media", Name: "Media", Pool: i.pool, Dataset: i.pool + "/shares/media"},
		{Kind: replica.KindVM, ID: "web", Name: "Web", Pool: i.pool, Dataset: i.pool + "/vms/web"},
	}, nil
}

func (i itemsOn) Resolve(_ context.Context, kind, id string) (string, error) {
	switch kind + "/" + id {
	case "share/media":
		return i.pool + "/shares/media", nil
	case "vm/web":
		return i.pool + "/vms/web", nil
	}
	return "", replica.ErrNotFound
}

// restorer adopts restored shared folders the simple way (the real one is
// priv.ReplicationItems with the shares manager).
type restorer struct{}

func (restorer) ShareProps(_ context.Context, pool, id, name string) ([]string, error) {
	return []string{"org.hardyos:share=1", "org.hardyos:name=" + name}, nil
}
func (restorer) ShareAdopt(context.Context, string, string) error { return nil }
func (restorer) VMFree(context.Context, string) error             { return nil }
func (restorer) VMAdopt(context.Context, string) error            { return nil }
func (restorer) AppsPool(context.Context) (string, error)         { return "", replica.ErrNotFound }
func (restorer) AppAdopt(context.Context, string) error           { return nil }

// TestZFSReplicationIntegration replicates between two file-backed pools on
// one machine through two hardyd services talking mutual TLS over
// loopback: pairing, a full then an incremental send of a shared folder
// and a VM (with a zvol), an interrupted transfer resumed, the receiver
// refusing streams with properties or other names and names outside its
// place, properties on what it received, browsing, a restore as a new
// folder, and deleting a source's replicas. Needs root and ZFS; runs in
// CI's "ZFS integration" job (HARDYOS_ZFS_INTEGRATION=1).
func TestZFSReplicationIntegration(t *testing.T) {
	if os.Getenv("HARDYOS_ZFS_INTEGRATION") != "1" {
		t.Skip("set HARDYOS_ZFS_INTEGRATION=1 to run against real ZFS (needs root)")
	}
	if os.Geteuid() != 0 {
		t.Fatal("must run as root")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	dir := t.TempDir()
	run := func(name string, args ...string) string {
		t.Helper()
		out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s %v: %v\n%s", name, args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	get := func(prop, ds string) string { return run("zfs", "get", "-H", "-p", "-o", "value", prop, ds) }
	const src, dst = "hrsrc", "hrdst"
	for _, p := range []string{src, dst} {
		_ = exec.Command("zpool", "destroy", "-f", p).Run()
		vdev := filepath.Join(dir, p+".img")
		f, err := os.Create(vdev)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Truncate(512 << 20); err != nil {
			t.Fatal(err)
		}
		f.Close()
		run("zpool", "create", "-o", "ashift=12", "-m", filepath.Join(dir, "mnt", p), "-O", "compression=lz4", p, vdev)
		pool := p
		t.Cleanup(func() { _ = exec.Command("zpool", "destroy", "-f", pool).Run() })
	}
	run("zfs", "create", "-p", "-o", "org.hardyos:share=1", "-o", "org.hardyos:name=Media", src+"/shares/media")
	run("zfs", "create", "-p", "-o", "org.hardyos:vm=web", src+"/vms/web")
	run("zfs", "create", "-s", "-V", "64M", "-o", "volblocksize=16K", src+"/vms/web/disk0")
	mediaDir := get("mountpoint", src+"/shares/media")
	if err := os.WriteFile(filepath.Join(mediaDir, "hello.txt"), []byte("first"), 0o644); err != nil {
		t.Fatal(err)
	}

	m := &replica.Manager{Runner: sysexec.Exec{}, Items: itemsOn{src}, Restore: restorer{}, BrowseDir: filepath.Join(dir, "browse")}
	a, b := newNode(t, "alpha"), newNode(t, "bravo")
	a.svc.Root, b.svc.Root = &LocalRoot{M: m}, &LocalRoot{M: m}
	b.serve(t)
	tgt := pairOn(t, a, b, dst)
	srcID := tgt.SourceID
	task := &Task{Name: "Integration", TargetID: tgt.ID, IntervalMinutes: 60, KeepLocal: 2, KeepRemote: 2, Enabled: true,
		Items: []replica.Item{{Kind: replica.KindShare, ID: "media"}, {Kind: replica.KindVM, ID: "web"}}}
	if _, err := a.svc.saveTask(ctx, task); err != nil {
		t.Fatal(err)
	}

	// Full copy.
	if j := a.run(t, task.ID); j.State != jobs.Succeeded {
		t.Fatal(j.Error)
	}
	rMedia := dst + "/replicas/" + srcID + "/share/media"
	rDisk := dst + "/replicas/" + srcID + "/vm/web/disk0"
	for ds, want := range map[string]map[string]string{
		rMedia: {"readonly": "on", "canmount": "off", "mounted": "no", "org.hardyos:replica": srcID, "org.hardyos:share": "-", "org.hardyos:name": "-",
			"mountpoint": "/mnt/" + dst + "/replicas/" + srcID + "/share/media", "sharenfs": "off", "exec": "off"},
		rDisk:                      {"readonly": "on", "volmode": "none", "org.hardyos:vm": "-", "org.hardyos:replica": srcID},
		dst + "/replicas":          {"canmount": "off", "org.hardyos:role": "replicas"},
		dst + "/replicas/" + srcID: {"canmount": "off", "org.hardyos:replica": srcID},
	} {
		for prop, v := range want {
			if got := get(prop, ds); got != v {
				t.Errorf("%s %s = %q, want %q", ds, prop, got, v)
			}
		}
	}
	if _, err := os.Stat("/dev/zvol/" + rDisk); err == nil {
		t.Error("the replica's zvol has a device node (volmode=none)")
	}

	// Incremental.
	if err := os.WriteFile(filepath.Join(mediaDir, "second.txt"), []byte("second"), 0o644); err != nil {
		t.Fatal(err)
	}
	if j := a.run(t, task.ID); j.State != jobs.Succeeded {
		t.Fatal(j.Error)
	}
	snaps := strings.Fields(run("zfs", "list", "-H", "-o", "name", "-t", "snapshot", "-d", "1", rMedia))
	if len(snaps) != 2 {
		t.Fatalf("replica snapshots: %v", snaps)
	}

	// An interrupted transfer: a big file at 1 MiB/s, cancelled after a few
	// seconds, leaves a resume token; the next run finishes it.
	big := make([]byte, 48<<20)
	_, _ = rand.Read(big)
	if err := os.WriteFile(filepath.Join(mediaDir, "big.bin"), big, 0o644); err != nil {
		t.Fatal(err)
	}
	task.BandwidthKBps = 1024
	if _, err := a.svc.saveTask(ctx, task); err != nil {
		t.Fatal(err)
	}
	j, err := a.svc.RunNow(ctx, task.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	// At 1 MiB/s the 48 MiB (incompressible) take most of a minute.
	time.Sleep(10 * time.Second)
	if err := a.svc.Cancel(ctx, task.ID); err != nil {
		t.Fatal(err)
	}
	if done := a.wait(t, j); done.State != jobs.Cancelled {
		t.Fatalf("cancelled run: %s %s", done.State, done.Error)
	}
	time.Sleep(2 * time.Second) // zfs receive saves its state as it exits
	if tok := get("receive_resume_token", rMedia); tok == "-" || tok == "" {
		t.Fatal("no resume token after the interrupted transfer")
	}
	task.BandwidthKBps = 0
	if _, err := a.svc.saveTask(ctx, task); err != nil {
		t.Fatal(err)
	}
	if j := a.run(t, task.ID); j.State != jobs.Succeeded {
		t.Fatal(j.Error)
	}
	if tok := get("receive_resume_token", rMedia); tok != "-" {
		t.Fatalf("token left: %s", tok)
	}
	last := strings.Fields(run("zfs", "list", "-H", "-o", "name", "-t", "snapshot", "-d", "1", "-s", "createtxg", rMedia))
	lastLabel := last[len(last)-1][strings.Index(last[len(last)-1], "@")+1:]
	// B keeps max(the task's 2, its own minimum 3); the rest are pruned.
	if len(last) != 3 {
		t.Fatalf("replica snapshots after pruning: %v", last)
	}

	// The receiver refuses streams with properties (-p), packages (-R), a
	// stream for another snapshot, and names outside its place.
	tg := replica.Target{Pool: dst, Source: srcID, Kind: replica.KindShare, Item: "evil"}
	for name, args := range map[string][]string{
		"props":   {"send", "-p", src + "/shares/media@" + lastLabel},
		"package": {"send", "-R", src + "/shares/media@" + lastLabel},
	} {
		rs, w, err := m.Recv(ctx, replica.RecvArgs{Target: tg, Task: task.ID, Snapshot: lastLabel})
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.CommandContext(ctx, "zfs", args...)
		cmd.Stdout = w
		_ = cmd.Run()
		w.Close()
		st := waitStream(t, m, rs.Stream)
		if st.OK || !strings.Contains(st.Error, "package") {
			t.Errorf("%s stream: %+v", name, st)
		}
		if out, err := exec.Command("zfs", "list", tg.Dataset()).CombinedOutput(); err == nil {
			t.Errorf("%s stream created %s: %s", name, tg.Dataset(), out)
		}
	}
	other := "hardyos-repl-" + task.ID + "-20200101T000000Z"
	rs, w, err := m.Recv(ctx, replica.RecvArgs{Target: tg, Task: task.ID, Snapshot: other})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, "zfs", "send", src+"/shares/media@"+lastLabel)
	cmd.Stdout = w
	_ = cmd.Run()
	w.Close()
	if st := waitStream(t, m, rs.Stream); st.OK {
		t.Error("a stream for another snapshot was received")
	}
	for _, bad := range []replica.Target{
		{Pool: dst, Source: srcID, Kind: replica.KindShare, Item: "../../" + src},
		{Pool: dst, Source: "../" + srcID, Kind: replica.KindShare, Item: "media"},
		{Pool: dst, Source: srcID, Kind: replica.KindShare, Item: "media", Child: "../../x"},
	} {
		if _, _, err := m.Recv(ctx, replica.RecvArgs{Target: bad, Task: task.ID, Snapshot: lastLabel}); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
	// A full stream over an existing replica is refused (no -F, nothing overwritten).
	rs, w, err = m.Recv(ctx, replica.RecvArgs{Target: replica.Target{Pool: dst, Source: srcID, Kind: replica.KindShare, Item: "media"}, Task: task.ID, Snapshot: lastLabel})
	if err == nil {
		cmd := exec.CommandContext(ctx, "zfs", "send", src+"/shares/media@"+lastLabel)
		cmd.Stdout = w
		_ = cmd.Run()
		w.Close()
		if st := waitStream(t, m, rs.Stream); st.OK {
			t.Error("a full stream replaced a replica")
		}
	}

	// Browse the replica's newest snapshot (mounted read-only for a moment).
	br, err := a.svc.TargetBrowse(ctx, tgt.ID, replica.KindShare, "media", "", lastLabel, "/")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range br.Entries {
		names = append(names, e.Name)
	}
	if !strings.Contains(strings.Join(names, ","), "hello.txt") || !strings.Contains(strings.Join(names, ","), "big.bin") {
		t.Fatalf("browse: %v", names)
	}
	if get("mounted", rMedia) != "no" {
		t.Fatal("the replica stayed mounted")
	}

	// Restore it as a new shared folder on the source.
	j = a.submit(t, JobRestore, RestoreParams{Target: tgt.ID, Kind: replica.KindShare, ID: "media", Snapshot: lastLabel, Pool: src, NewID: "media-restored", Name: "Media (restored)"})
	if j.State != jobs.Succeeded {
		t.Fatal(j.Error)
	}
	restored := src + "/shares/media-restored"
	if get("org.hardyos:restoring", restored) != "-" || !strings.HasPrefix(get("org.hardyos:restored", restored), "bravo@") || get("mounted", restored) != "yes" {
		t.Fatal("restored copy properties")
	}
	got, err := os.ReadFile(filepath.Join(get("mountpoint", restored), "big.bin"))
	if err != nil || !bytes.Equal(got, big) {
		t.Fatal("restored data differs", err)
	}

	// Deleting the source's replicas on B.
	srcRec, _ := b.svc.Store().Source(ctx, srcID)
	if j := b.submit(t, JobSourceDelete, SourceDeleteParams{Source: srcID, DeleteReplicas: true, Confirm: srcRec.Name}); j.State != jobs.Succeeded {
		t.Fatal(j.Error)
	}
	if out, err := exec.Command("zfs", "list", dst+"/replicas/"+srcID).CombinedOutput(); err == nil {
		t.Fatalf("replicas left: %s", out)
	}
	// The task's own snapshots on the source go with the task; others stay.
	run("zfs", "snapshot", src+"/shares/media@manual-keep")
	if j := a.submit(t, JobTaskDelete, TaskDeleteParams{Task: task.ID, Confirm: task.Name}); j.State != jobs.Succeeded {
		t.Fatal(j.Error)
	}
	left := run("zfs", "list", "-H", "-o", "name", "-t", "snapshot", "-r", src)
	if strings.Contains(left, replica.SnapPrefix) || !strings.Contains(left, "manual-keep") {
		t.Fatalf("snapshots left on the source:\n%s", left)
	}
}

func waitStream(t *testing.T, m *replica.Manager, id string) *replica.StreamState {
	t.Helper()
	for i := 0; i < 600; i++ {
		st, err := m.Stream(id)
		if err != nil {
			t.Fatal(err)
		}
		if st.Done {
			return st
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("stream didn't finish")
	return nil
}
