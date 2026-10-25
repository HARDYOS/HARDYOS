package install

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/hw"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

const (
	diskA = "/dev/disk/by-id/ata-Samsung_SSD_870_A"
	diskB = "/dev/disk/by-id/ata-Samsung_SSD_870_B"
)

func goodPlan() Plan {
	return Plan{Disks: []string{diskA, diskB}, Hostname: "nas", Timezone: "America/Chicago", Network: Network{Mode: "dhcp"}}
}

func TestPlanValidate(t *testing.T) {
	if err := (&Plan{Disks: []string{"/dev/sda"}, Hostname: "nas", Timezone: "UTC", Network: Network{Mode: "dhcp"}}).Validate(); err != nil {
		t.Errorf("kernel path for a disk without by-id: %v", err)
	}
	bad := map[string]func(p *Plan){
		"no disks":        func(p *Plan) { p.Disks = nil },
		"duplicate disk":  func(p *Plan) { p.Disks = []string{diskA, diskA} },
		"partition":       func(p *Plan) { p.Disks = []string{diskA + "-part1"} },
		"traversal":       func(p *Plan) { p.Disks = []string{"/dev/disk/by-id/../sda"} },
		"hostname":        func(p *Plan) { p.Hostname = "Bad_Host" },
		"hostname dash":   func(p *Plan) { p.Hostname = "-nas" },
		"timezone":        func(p *Plan) { p.Timezone = "../../etc/passwd" },
		"mode":            func(p *Plan) { p.Network.Mode = "pppoe" },
		"static no iface": func(p *Plan) { p.Network = Network{Mode: "static", Address: "192.168.1.5/24"} },
		"static net addr": func(p *Plan) { p.Network = Network{Mode: "static", Interface: "eno1", Address: "192.168.1.0/24"} },
		"static bare ip":  func(p *Plan) { p.Network = Network{Mode: "static", Interface: "eno1", Address: "192.168.1.5"} },
		"gateway outside": func(p *Plan) {
			p.Network = Network{Mode: "static", Interface: "eno1", Address: "192.168.1.5/24", Gateway: "10.0.0.1"}
		},
		"bad dns": func(p *Plan) {
			p.Network = Network{Mode: "static", Interface: "eno1", Address: "192.168.1.5/24", DNS: []string{"dns.example"}}
		},
	}
	for name, mutate := range bad {
		p := goodPlan()
		mutate(&p)
		if err := p.Validate(); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	p := goodPlan()
	p.Network = Network{Mode: "static", Interface: "eno1", Address: "192.168.1.5/24", Gateway: "192.168.1.1", DNS: []string{"1.1.1.1", "2606:4700:4700::1111"}}
	if err := p.Validate(); err != nil {
		t.Errorf("static plan: %v", err)
	}
}

func TestPartitionPaths(t *testing.T) {
	cases := map[string]string{
		diskA:          diskA + "-part3",
		"/dev/sda":     "/dev/sda3",
		"/dev/nvme0n1": "/dev/nvme0n1p3",
		"/dev/vdb":     "/dev/vdb3",
	}
	for disk, want := range cases {
		if got := Partition(disk, 3); got != want {
			t.Errorf("Partition(%s) = %s, want %s", disk, got, want)
		}
	}
}

func TestRenderInterfaces(t *testing.T) {
	dhcp := RenderInterfaces(Network{Mode: "dhcp"}, []string{"eno1", "eno2"})
	if !strings.Contains(dhcp, "iface eno1 inet dhcp") || !strings.Contains(dhcp, "iface eno2 inet dhcp") {
		t.Errorf("dhcp:\n%s", dhcp)
	}
	static := RenderInterfaces(Network{Mode: "static", Interface: "eno2", Address: "10.0.0.5/24", Gateway: "10.0.0.1"}, []string{"eno1", "eno2"})
	for _, want := range []string{"iface eno1 inet dhcp", "auto eno2\niface eno2 inet static\n\taddress 10.0.0.5/24\n\tgateway 10.0.0.1"} {
		if !strings.Contains(static, want) {
			t.Errorf("static missing %q:\n%s", want, static)
		}
	}
	if strings.Contains(static, "iface eno2 inet dhcp") {
		t.Error("static interface also got DHCP")
	}
	v6 := RenderInterfaces(Network{Mode: "static", Interface: "eno1", Address: "fd00::5/64"}, nil)
	if !strings.Contains(v6, "iface eno1 inet6 static") {
		t.Errorf("v6:\n%s", v6)
	}
}

func TestSeedValidate(t *testing.T) {
	hash, _ := auth.HashPassword("supersecret1")
	if err := (&Seed{Username: "cade", PasswordHash: hash}).Validate(); err != nil {
		t.Fatal(err)
	}
	for _, s := range []Seed{
		{Username: "Cade", PasswordHash: hash},
		{Username: "cade", PasswordHash: "plaintext"},
		{Username: "cade", PasswordHash: hash, DisplayName: "a\nb"},
	} {
		if err := s.Validate(); err == nil {
			t.Errorf("%+v: expected an error", s)
		}
	}
}

func TestEligible(t *testing.T) {
	ok := hw.Disk{ByID: diskA, SizeBytes: 250e9, Usage: hw.UsageFree}
	if err := Eligible(ok); err != nil {
		t.Error(err)
	}
	oldInstall := hw.Disk{ByID: diskA, SizeBytes: 250e9, Usage: hw.UsageBoot, Pool: "rpool"}
	if err := Eligible(oldInstall); err != nil {
		t.Errorf("a previous install's disk should be reusable: %v", err)
	}
	for _, d := range []hw.Disk{
		{ByID: diskA, SizeBytes: 32e9, Usage: hw.UsageMounted, UsageDetail: "sdc1 is mounted at /run/live/medium"},
		{ByID: diskA, SizeBytes: 250e9, Usage: hw.UsageBoot},
		{ByID: diskA, SizeBytes: 8e9, Usage: hw.UsageFree},
	} {
		if err := Eligible(d); err == nil {
			t.Errorf("%+v: expected an error", d)
		}
	}
}

// host builds a fake live system: medium, zoneinfo, disks and the unpacked
// image (as if unsquashfs had already run).
func host(t *testing.T) (*Installer, *sysexec.Fake, string) {
	t.Helper()
	root := t.TempDir()
	write := func(p, data string) {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("/run/live/medium/live/filesystem.squashfs", "sqfs")
	write("/run/live/medium/live/vmlinuz-6.12.10-amd64", "kernel")
	write("/usr/share/zoneinfo/America/Chicago", "tz")
	write("/etc/hostid", "\x01\x02\x03\x04")
	for _, d := range []string{diskA, diskB} {
		write(d+"-part2", "")
		write(d+"-part3", "")
	}
	write("/sys/class/net/eno1/device/vendor", "0x8086")
	write("/sys/class/net/lo/address", "00:00:00:00:00:00")
	// Unpacked image: modules, passwd, a live marker and SSH keys to clean up.
	write("/target/lib/modules/6.12.10-amd64/modules.dep", "")
	write("/target/etc/passwd", "root:x:0:0:root:/root:/bin/bash\nhardyd:x:998:997::/var/lib/hardyos:/usr/sbin/nologin\n")
	write("/target/etc/hardyos/live-installer", "")
	write("/target/etc/ssh/ssh_host_ed25519_key", "old")
	write("/target/etc/machine-id", "0123456789abcdef")

	f := &sysexec.Fake{}
	f.OnPrefix("", sysexec.Result{}) // every command succeeds unless overridden
	f.OnResult("zpool list -H rpool", sysexec.Result{ExitCode: 1, Stderr: []byte("cannot open 'rpool': no such pool")})
	f.On("chroot /target dpkg-query -W -f=${Package} ${db:Status-Status}\\n live-boot live-boot-initramfs-tools live-config live-config-systemd live-tools",
		"live-boot installed\nlive-config installed\nlive-tools not-installed\n")
	f.On("blkid -s PARTUUID -o value "+diskA+"-part2", "aaaaaaaa-0000-0000-0000-000000000001\n")
	f.On("blkid -s PARTUUID -o value "+diskB+"-part2", "aaaaaaaa-0000-0000-0000-000000000002\n")
	f.On("zfs list -H -p -o name,creation,org.hardyos:version -d 1 -r rpool/ROOT",
		"rpool/ROOT\t100\t-\nrpool/ROOT/hardyos-0.1.0\t200\t0.1.0\n")
	f.On("zpool get -H -o value bootfs rpool", "rpool/ROOT/hardyos-0.1.0\n")

	in := &Installer{
		Runner: f, Root: root, Version: "0.1.0", SettleTimeout: time.Second,
		ListDisks: func(context.Context) ([]hw.Disk, error) {
			return []hw.Disk{
				{Name: "sda", ByID: diskA, SizeBytes: 250e9, Kind: hw.KindSSD, Usage: hw.UsageFree, Partitions: []hw.Partition{}},
				{Name: "sdb", ByID: diskB, SizeBytes: 500e9, Kind: hw.KindSSD, Usage: hw.UsageBoot, Pool: "rpool",
					Partitions: []hw.Partition{{Name: "sdb3", FSType: "zfs_member", Label: "rpool"}}},
				{Name: "sdc", ByID: "/dev/disk/by-id/usb-Live", SizeBytes: 32e9, Usage: hw.UsageMounted, UsageDetail: "sdc1 is mounted at /run/live/medium", Removable: true},
			}, nil
		},
	}
	return in, f, root
}

func TestCheckWarnsAndRejects(t *testing.T) {
	in, _, _ := host(t)
	checks, err := in.Check(context.Background(), goodPlan())
	if err != nil {
		t.Fatal(err)
	}
	b := strings.Join(checks[1].Warnings, "; ")
	if !strings.Contains(b, "member of pool rpool") || !strings.Contains(b, "larger than the other boot disk") {
		t.Errorf("disk B warnings: %s", b)
	}
	p := goodPlan()
	p.Disks = []string{"/dev/disk/by-id/usb-Live"}
	if _, err := in.Check(context.Background(), p); err == nil || !strings.Contains(err.Error(), "in use") {
		t.Errorf("live medium: %v", err)
	}
	p = goodPlan()
	p.Timezone = "Mars/Olympus"
	if _, err := in.Check(context.Background(), p); err == nil {
		t.Error("expected unknown timezone error")
	}
}

func TestFullInstall(t *testing.T) {
	in, f, root := host(t)
	ctx := context.Background()
	p := goodPlan()
	hash, _ := auth.HashPassword("supersecret1")
	seed := Seed{Username: "cade", DisplayName: "Cade Hardy", PasswordHash: hash}

	if err := in.Partition(ctx, p, false); err == nil {
		t.Fatal("partition without confirmWipe must fail")
	}
	if err := in.Partition(ctx, p, true); err != nil {
		t.Fatal(err)
	}
	if err := in.CreatePool(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := in.CopySystem(ctx); err != nil {
		t.Fatal(err)
	}
	if err := in.Configure(ctx, p, seed); err != nil {
		t.Fatal(err)
	}
	// update-initramfs is faked: put the initramfs where it would have written it.
	_ = os.WriteFile(filepath.Join(root, "target/boot/initrd.img-6.12.10-amd64"), []byte("initrd"), 0o644)
	if err := in.InstallBootloader(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := in.Finish(ctx); err != nil {
		t.Fatal(err)
	}

	lines := strings.Join(f.Lines(), "\n")
	for _, want := range []string{
		"sgdisk --zap-all " + diskA,
		"-n2:1M:+1G -t2:EF00",
		"mkfs.vfat -F 32 -n HARDYOS-EFI " + diskB + "-part2",
		"zpool create -f -o ashift=12",
		"-R /target rpool mirror " + diskA + "-part3 " + diskB + "-part3",
		"zfs create -o canmount=noauto -o mountpoint=/ -o org.hardyos:version=0.1.0 rpool/ROOT/hardyos-0.1.0",
		"zfs create -o mountpoint=/var/lib/hardyos rpool/hardyos",
		"zpool set bootfs=rpool/ROOT/hardyos-0.1.0 rpool",
		"unsquashfs -f -no-progress -d /target /run/live/medium/live/filesystem.squashfs",
		"chroot /target env DEBIAN_FRONTEND=noninteractive dpkg --purge live-boot live-config",
		"chroot /target ssh-keygen -A",
		"chroot /target update-initramfs -c -k 6.12.10-amd64",
		"grub-install --target=",
		"blkid -l -o device -t PARTUUID=aaaaaaaa-0000-0000-0000-000000000002",
		"mount -t vfat -o umask=0077 /dev/disk/by-partuuid/aaaaaaaa-0000-0000-0000-000000000002",
		"zpool export rpool",
	} {
		if !strings.Contains(lines, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(lines, "usb-Live") {
		t.Error("touched the live medium")
	}
	// The old rpool member had its labels cleared before partitioning.
	if !strings.Contains(lines, "zpool labelclear -f /dev/sdb3") {
		t.Error("old pool labels were not cleared")
	}

	read := func(p string) string {
		b, err := os.ReadFile(filepath.Join(root, "target", p))
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		return string(b)
	}
	if read("etc/hostname") != "nas\n" || !strings.Contains(read("etc/hosts"), "127.0.1.1\tnas") {
		t.Error("hostname not written")
	}
	if read("etc/machine-id") != "" {
		t.Error("machine-id not reset")
	}
	if read("etc/hostid") != "\x01\x02\x03\x04" {
		t.Error("hostid not copied")
	}
	if !strings.Contains(read("etc/network/interfaces"), "iface eno1 inet dhcp") {
		t.Error("network not configured")
	}
	if link, _ := os.Readlink(filepath.Join(root, "target/etc/localtime")); link != "/usr/share/zoneinfo/America/Chicago" {
		t.Errorf("localtime -> %q", link)
	}
	if read("boot/vmlinuz-6.12.10-amd64") != "kernel" {
		t.Error("kernel not copied from the medium")
	}
	for _, gone := range []string{"etc/hardyos/live-installer", "etc/ssh/ssh_host_ed25519_key"} {
		if _, err := os.Stat(filepath.Join(root, "target", gone)); err == nil {
			t.Errorf("%s should have been removed", gone)
		}
	}
	var got Seed
	if err := json.Unmarshal([]byte(read("var/lib/hardyos/install-seed.json")), &got); err != nil || got != seed {
		t.Errorf("seed = %+v, %v", got, err)
	}
	if fi, _ := os.Stat(filepath.Join(root, "target/var/lib/hardyos/install-seed.json")); fi.Mode().Perm() != 0o600 {
		t.Errorf("seed mode %v", fi.Mode().Perm())
	}
	if !strings.Contains(read("var/lib/hardyos/boot.json"), "aaaaaaaa-0000-0000-0000-000000000002") {
		t.Error("boot.json missing the second disk")
	}
	if !strings.Contains(read("../run/hardyos/boot/esp1/grub/grub.cfg"), "root=ZFS=rpool/ROOT/hardyos-0.1.0") {
		t.Error("grub.cfg not written to the second ESP")
	}
}
