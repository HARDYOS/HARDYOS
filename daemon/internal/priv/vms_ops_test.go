package priv

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/shares"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
	"github.com/hardyos/hardyos/daemon/internal/vms"
)

func vmServer(t *testing.T, fake *sysexec.Fake) *Client {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	sock := filepath.Join(t.TempDir(), "priv.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{AllowedUIDs: []uint32{uint32(os.Getuid())}}
	arch, _ := vms.ArchFor("amd64")
	m := &vms.Manager{Runner: fake, Root: t.TempDir(), Arch: &arch,
		Mounts: shares.MountFunc(func(string, string) (uint64, error) { return 1, nil })}
	RegisterVMs(s, m)
	go func() { _ = s.Serve(ctx, ln) }()
	return NewClient(sock)
}

func TestVMOps(t *testing.T) {
	fake := &sysexec.Fake{}
	fake.On("zfs list -H -p -t filesystem -o name,mountpoint,org.hardyos:vm", "tank\t/mnt/tank\t-\ntank/vms\t/mnt/tank/vms\t-\n")
	fake.On("zfs list -H -p -t filesystem -o name,used,org.hardyos:kept", "tank/vms/old-kept-20261026-120000\t1024\told\n")
	fake.OnPrefix("virsh -c qemu:///system -q domstats", sysexec.Result{})
	fake.On("zpool list -H -o name,health", "tank\tONLINE\n")
	pc := vmServer(t, fake)
	ctx := context.Background()

	var o vms.Overview
	if err := pc.Call(ctx, OpVMsList, nil, &o); err != nil {
		t.Fatal(err)
	}
	if len(o.VMs) != 0 || len(o.Kept) != 1 || o.Kept[0].VM != "old" {
		t.Fatalf("overview = %+v", o)
	}

	var pe *Error
	if err := pc.Call(ctx, OpVMsGet, VMRef{ID: "nope"}, nil); !errors.As(err, &pe) || pe.Code != CodeBadArgs {
		t.Fatalf("unknown VM: %v", err)
	}
	// hardyd can't hand root a domain definition: only a spec, checked.
	err := pc.Call(ctx, OpVMsCreate, map[string]any{"spec": map[string]any{"id": "x"}, "xml": "<domain/>"}, nil)
	if !errors.As(err, &pe) || pe.Code != CodeBadArgs || !strings.Contains(pe.Message, "unknown field") {
		t.Fatalf("xml field: %v", err)
	}
	err = pc.Call(ctx, OpVMsCreate, vms.CreateArgs{Spec: vms.Spec{ID: "Bad!", Template: "linux", OS: "linux", Pool: "tank"}}, nil)
	if !errors.As(err, &pe) || pe.Code != CodeBadArgs || !strings.Contains(pe.Message, "isn't a valid VM name") {
		t.Fatalf("bad spec: %v", err)
	}
	if err := pc.Call(ctx, OpVMsConsole, vms.ConsoleArgs{ID: "nope"}, nil); !errors.As(err, &pe) || pe.Code != CodeBadArgs {
		t.Fatalf("console of an unknown VM: %v", err)
	}
	if _, err := pc.CallFile(ctx, OpVMsConsoleOpen, vms.ConsoleOpenArgs{ID: "nope", Token: strings.Repeat("a", 64)}, nil); !errors.As(err, &pe) || pe.Code != CodeBadArgs {
		t.Fatalf("console with a made-up token: %v", err)
	}
	if err := pc.Call(ctx, OpVMsBridge, nil, nil); !errors.As(err, &pe) || pe.Code != CodeBadArgs {
		t.Fatalf("bridge without a network manager: %v", err)
	}
	var c vms.Capabilities
	if err := pc.Call(ctx, OpVMsCapabilities, nil, &c); err != nil || c.Arch.Machine != "q35" || len(c.Pools) != 1 {
		t.Fatalf("capabilities = %+v %v", c, err)
	}
	var lib vms.LibraryView
	if err := pc.Call(ctx, OpVMsISOList, nil, &lib); !errors.As(err, &pe) {
		t.Fatalf("library without the shares code: %+v %v", lib, err)
	}
}
