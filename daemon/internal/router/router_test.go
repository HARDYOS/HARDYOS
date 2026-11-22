package router

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/store"
)

func TestDefault(t *testing.T) {
	dir := t.TempDir()
	routeFile, arpFile = filepath.Join(dir, "route"), filepath.Join(dir, "arp")
	t.Cleanup(func() { routeFile, arpFile = "/proc/net/route", "/proc/net/arp" })
	// The kernel prints addresses in this machine's byte order.
	hexAddr := func(a, b, c, d byte) string {
		return fmt.Sprintf("%08X", binary.NativeEndian.Uint32([]byte{a, b, c, d}))
	}
	os.WriteFile(routeFile, []byte("Iface\tDestination\tGateway\tFlags\nenp1s0\t"+hexAddr(192, 168, 1, 0)+"\t00000000\t0001\nenp1s0\t00000000\t"+hexAddr(192, 168, 1, 1)+"\t0003\n"), 0o600)
	os.WriteFile(arpFile, []byte("IP address       HW type     Flags       HW address            Mask     Device\n192.168.1.1      0x1         0x2         AA:BB:CC:00:11:22     *        enp1s0\n"), 0o600)
	ip, mac := Default()
	if ip.String() != "192.168.1.1" || mac != "aa:bb:cc:00:11:22" {
		t.Fatalf("default = %v %q", ip, mac)
	}
}

func TestTrust(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "h.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if Load(ctx, db) != nil {
		t.Fatal("on by default")
	}
	ip := netip.MustParseAddr("192.168.1.1")
	if _, err := Trust(ctx, db, ip, "", "x"); err != ErrNoRouter {
		t.Fatalf("no MAC: %v", err)
	}
	if _, err := Trust(ctx, db, ip, "AA:bb:cc:00:11:22", "cade"); err != nil {
		t.Fatal(err)
	}
	tr := Load(ctx, db)
	if !tr.Matches(ip, "aa:bb:cc:00:11:22") || tr.Matches(ip, "aa:bb:cc:00:11:23") || tr.Matches(netip.MustParseAddr("192.168.1.254"), "aa:bb:cc:00:11:22") {
		t.Fatalf("matches %+v", tr)
	}
	if err := Untrust(ctx, db); err != nil || Load(ctx, db) != nil {
		t.Fatalf("untrust %v", err)
	}
}
