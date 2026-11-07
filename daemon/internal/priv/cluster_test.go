package priv

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster/fence"
	"github.com/hardyos/hardyos/daemon/internal/vms"
)

func TestLibvirtHookChecksOnlyMigrations(t *testing.T) {
	s := &Server{AllowedUIDs: []uint32{uint32(os.Getuid())}}
	var got []vms.MigrateCheckArgs
	s.Handle(OpVMsMigrateCheck, typed(func(_ context.Context, a vms.MigrateCheckArgs) (any, error) {
		got = append(got, a)
		if a.VM != "web" {
			return nil, Errorf(CodeBadArgs, "no live migration of this VM is expected here")
		}
		return map[string]bool{"ok": true}, nil
	}))
	sock := startServer(t, s)
	var stderr bytes.Buffer
	if rc := LibvirtHookMain([]string{"web", "start", "begin", "-"}, strings.NewReader("<domain/>"), &stderr, sock); rc != 0 || len(got) != 0 {
		t.Fatalf("a start was checked: rc %d", rc)
	}
	if rc := LibvirtHookMain([]string{"web", "migrate", "begin", "-"}, strings.NewReader("<domain><name>web</name></domain>"), &stderr, sock); rc != 0 {
		t.Fatalf("an admitted migration was refused: %s", stderr.String())
	}
	if len(got) != 1 || !strings.Contains(got[0].XML, "<name>web</name>") {
		t.Fatalf("%+v", got)
	}
	if rc := LibvirtHookMain([]string{"evil", "migrate", "begin", "-"}, strings.NewReader("<domain/>"), &stderr, sock); rc == 0 {
		t.Fatal("an unadmitted migration was accepted")
	}
	// No answer from hardyd-priv: refused.
	if rc := LibvirtHookMain([]string{"web", "migrate", "begin", "-"}, strings.NewReader("<domain/>"), &stderr, sock+".gone"); rc == 0 {
		t.Fatal("accepted without hardyd-priv")
	}
}

type dev struct{ pets int }

func (d *dev) SetTimeout(s int) (int, error) { return s, nil }
func (d *dev) Keepalive() error              { d.pets++; return nil }
func (d *dev) Close(bool) error              { return nil }

func TestWatchdogOps(t *testing.T) {
	s := &Server{AllowedUIDs: []uint32{uint32(os.Getuid())}}
	d := &dev{}
	f := &fence.Feeder{Open: func() (fence.Device, string, error) { return d, fence.KindHardware, nil }, Interval: time.Hour}
	RegisterClusterFence(s, f, nil, nil)
	c := NewClient(startServer(t, s))
	ctx := context.Background()
	if err := c.Call(ctx, OpClusterWatchdogPet, WatchdogPetArgs{ValidForMs: 1000}, nil); err == nil {
		t.Fatal("pet before arm")
	}
	var arm WatchdogArmResult
	if err := c.Call(ctx, OpClusterWatchdogArm, WatchdogArmArgs{TimeoutSec: 10}, &arm); err != nil || arm.Kind != fence.KindHardware {
		t.Fatalf("%+v %v", arm, err)
	}
	if err := c.Call(ctx, OpClusterWatchdogPet, WatchdogPetArgs{ValidForMs: int64(time.Hour / time.Millisecond)}, nil); err == nil {
		t.Fatal("a pet valid for an hour")
	}
	if err := c.Call(ctx, OpClusterWatchdogPet, WatchdogPetArgs{ValidForMs: 15000}, nil); err != nil {
		t.Fatal(err)
	}
	var st fence.Status
	if err := c.Call(ctx, OpClusterWatchdogStatus, nil, &st); err != nil || !st.Armed || st.PettingForMs <= 0 {
		t.Fatalf("%+v %v", st, err)
	}
	if err := c.Call(ctx, OpClusterWatchdogDisarm, nil, nil); err != nil {
		t.Fatal(err)
	}
	// Self-fence validates its ids and fails without engines.
	var pe *Error
	err := c.Call(ctx, OpClusterSelfFence, SelfFenceArgs{VMs: []string{"../x"}}, nil)
	if !errors.As(err, &pe) || pe.Code != CodeBadArgs {
		t.Fatalf("a bad id: %v", err)
	}
	if err := c.Call(ctx, OpClusterSelfFence, SelfFenceArgs{VMs: []string{"web"}}, nil); err == nil {
		t.Fatal("reported stopped without a VM engine")
	}
	raw, _ := json.Marshal(map[string]any{"timeoutSec": 10, "extra": 1})
	if err := c.Call(ctx, OpClusterWatchdogArm, json.RawMessage(raw), nil); err == nil {
		t.Fatal("unknown fields accepted")
	}
}
