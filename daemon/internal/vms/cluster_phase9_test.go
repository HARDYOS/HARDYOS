package vms

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// A live migration is refused while an unattended install is pending or
// game streaming is published (decision 470).
func TestMigrationRefusesPendingInstallAndStreaming(t *testing.T) {
	s := fromTemplate(t, "web", "linux")
	s.Unattend = &Unattend{Pending: true}
	s.Media = append(s.Media, Media{Kind: MediaUnattend})
	if err := liveMigratable(s); err == nil || !strings.Contains(err.Error(), "installing") {
		t.Fatalf("a pending unattended install: %v", err)
	}
	s.Unattend, s.Media = nil, nil
	s.Streaming = &Streaming{Sunshine: true, Remote: true, Peers: []string{"100.64.0.9"}}
	if err := liveMigratable(s); err == nil || !strings.Contains(err.Error(), "streaming") {
		t.Fatalf("published streaming: %v", err)
	}
	s.Streaming.Remote = false
	if err := liveMigratable(s); err != nil {
		t.Fatalf("streaming set up but not published: %v", err)
	}
}

// USB devices plugged in by hand keep a VM on its server: the source's
// socket isn't made, and the send is refused under the lock too.
func TestMigrationRefusesHotpluggedUSB(t *testing.T) {
	e, _ := clusterEnv(t)
	ctx := context.Background()
	e.m.statsMu.Lock()
	e.m.hotplugged = map[string][]string{"web": {"046d:c52b"}}
	e.m.statsMu.Unlock()
	token := strings.Repeat("ab", 16)
	if _, err := e.m.MigrateListen(ctx, MigrateListenArgs{VM: "web", Token: token}); err == nil || !strings.Contains(err.Error(), "046d:c52b") {
		t.Fatalf("listen with a hot-plugged device: %v", err)
	}
	if err := e.m.MigrateSend(ctx, MigrateSendArgs{VM: "web", To: "c2", Token: token, MigrateURI: "tcp://10.77.0.22:49152", Generation: 3}); err == nil {
		t.Fatal("send with a hot-plugged device")
	}
}

// Per-server VM features are refused for a VM on cluster storage, and the
// scheduler leaves its snapshots to the storage server (decision 471).
func TestClusterVMRefusesPerServerFeatures(t *testing.T) {
	e, _ := clusterEnv(t)
	ctx := context.Background()
	refused := func(what string, err error) {
		t.Helper()
		if err == nil || !strings.Contains(err.Error(), "cluster storage") {
			t.Errorf("%s: %v", what, err)
		}
	}
	_, err := e.m.SetSchedule(ctx, SetScheduleArgs{ID: "web", Schedule: &Schedule{Daily: 7}})
	refused("schedule", err)
	_, err = e.m.MakeTemplate(ctx, MakeTemplateArgs{VM: "web", ID: "web-tpl", Name: "Web"})
	refused("template", err)
	e.m.Devices = &fakeHotplug{fakeDevices: e.devs}
	a := USBArgs{ID: "web", Device: "046d:c52b", Persist: true}
	_, err = e.m.AttachUSB(ctx, a)
	refused("persisted USB attach", err)
	_, err = e.m.DetachUSB(ctx, a)
	refused("persisted USB detach", err)
}

func TestClusterVMRefusesStreamingPublish(t *testing.T) {
	e, _ := clusterEnv(t)
	s := fromTemplate(t, "web", "windows11")
	s.Streaming = &Streaming{Sunshine: true, User: SunshineUser, CertSHA256: strings.Repeat("a", 64)}
	b, _ := json.Marshal(s)
	write(t, filepath.Join(e.root, "/mnt/hc/tank/vms/web", specFile), string(b))
	_, err := e.m.SetStreamingRemote(context.Background(), StreamingPublishArgs{ID: "web", Enabled: true, Peers: []string{"100.64.0.9"}})
	if err == nil || !strings.Contains(err.Error(), "cluster storage") {
		t.Fatalf("publishing a cluster VM's streaming: %v", err)
	}
}
