package hacopy

import (
	"context"
	"errors"
	"io"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/replica"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// fakeZFS is a small in-memory ZFS: datasets with a type, local
// properties and inheritance, enough for root's rules.
type fakeZFS struct {
	mu   sync.Mutex
	ds   map[string]map[string]string // name -> local props ("type" kept here)
	cmds []string
}

func newFake() *fakeZFS { return &fakeZFS{ds: map[string]map[string]string{}} }

func (f *fakeZFS) add(name, typ string, props ...string) {
	p := map[string]string{"type": typ}
	for i := 0; i+1 < len(props); i += 2 {
		p[props[i]] = props[i+1]
	}
	f.ds[name] = p
}

func (f *fakeZFS) get(name, prop string, inherit bool) string {
	for n := name; n != ""; {
		if v, ok := f.ds[n][prop]; ok {
			return v
		}
		if !inherit || !strings.HasPrefix(prop, "org.hardyos:") {
			break
		}
		i := strings.LastIndex(n, "/")
		if i < 0 {
			break
		}
		n = n[:i]
	}
	switch prop {
	case "mounted":
		return "no"
	case "used", "usedbydataset", "volsize":
		return "1073741824"
	case "guid":
		return "123456789"
	case "mountpoint":
		return "/mnt/" + name
	case "receive_resume_token":
		return "-"
	}
	return "-"
}

func ok(s string) (sysexec.Result, error) { return sysexec.Result{Stdout: []byte(s)}, nil }
func bad(s string) (sysexec.Result, error) {
	return sysexec.Result{Stderr: []byte(s), ExitCode: 1}, nil
}

func (f *fakeZFS) Run(_ context.Context, _ []byte, name string, args ...string) (sysexec.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cmds = append(f.cmds, name+" "+strings.Join(args, " "))
	if name == "zpool" {
		pools := map[string]bool{}
		for n := range f.ds {
			pools[strings.SplitN(n, "/", 2)[0]] = true
		}
		var l []string
		for p := range pools {
			l = append(l, p)
		}
		sort.Strings(l)
		return ok(strings.Join(l, "\n") + "\n")
	}
	last := args[len(args)-1]
	switch args[0] {
	case "list":
		if strings.Contains(strings.Join(args, " "), "-t snapshot") {
			return ok("")
		}
		if _, there := f.ds[last]; !there {
			return bad("dataset does not exist")
		}
		if args[1] == "-H" && args[2] == "-o" && args[3] == "type" {
			return ok(f.ds[last]["type"] + "\n")
		}
		cols := []string{"name", "type"}
		for i, a := range args {
			if a == "-o" {
				cols = strings.Split(args[i+1], ",")
			}
		}
		var out []string
		for n, p := range f.ds {
			if n == last || strings.HasPrefix(n, last+"/") {
				if strings.Contains(strings.Join(args, " "), "-d 1") && strings.Count(strings.TrimPrefix(n, last), "/") > 1 {
					continue
				}
				var row []string
				for _, c := range cols {
					switch c {
					case "name":
						row = append(row, n)
					case "type":
						row = append(row, p["type"])
					case "creation":
						row = append(row, "1000")
					default:
						row = append(row, f.get(n, c, true))
					}
				}
				out = append(out, strings.Join(row, "\t"))
			}
		}
		sort.Strings(out)
		return ok(strings.Join(out, "\n") + "\n")
	case "get":
		if _, there := f.ds[last]; !there {
			return bad("dataset does not exist")
		}
		if args[3] == "-s" { // get -H -p -s local,received -o value name ds
			v, has := f.ds[last][args[len(args)-2]]
			if !has {
				v = "-"
			}
			return ok(v + "\n")
		}
		var out []string
		for _, p := range strings.Split(args[len(args)-2], ",") {
			out = append(out, p+"\t"+f.get(last, p, true))
		}
		return ok(strings.Join(out, "\n") + "\n")
	case "set":
		for _, kv := range args[1 : len(args)-1] {
			k, v, _ := strings.Cut(kv, "=")
			f.ds[last][k] = v
		}
		return ok("")
	case "inherit":
		delete(f.ds[last], args[1])
		return ok("")
	case "create":
		p := map[string]string{"type": "filesystem"}
		for i := 1; i < len(args)-1; i++ {
			if args[i] == "-o" {
				k, v, _ := strings.Cut(args[i+1], "=")
				p[k] = v
				i++
			}
		}
		f.ds[last] = p
		return ok("")
	case "rename":
		from := args[1]
		for n, p := range f.ds {
			if n == from || strings.HasPrefix(n, from+"/") {
				delete(f.ds, n)
				f.ds[last+strings.TrimPrefix(n, from)] = p
			}
		}
		return ok("")
	case "destroy":
		for n := range f.ds {
			if n == last || strings.HasPrefix(n, last+"/") {
				delete(f.ds, n)
			}
		}
		return ok("")
	case "mount", "unmount", "snapshot":
		return ok("")
	}
	return bad("fake zfs: " + strings.Join(args, " "))
}

func vmRef(side Side) Ref { return Ref{Kind: cluster.KindVM, ID: "web", Pool: "tank", Side: side} }

func TestRefValidate(t *testing.T) {
	for _, r := range []Ref{
		{Kind: "disk", ID: "web", Pool: "tank", Side: SideLocal},
		{Kind: cluster.KindVM, ID: "Web", Pool: "tank", Side: SideLocal},
		{Kind: cluster.KindVM, ID: "web", Pool: "tank/x", Side: SideLocal},
		{Kind: cluster.KindVM, ID: "web", Pool: "tank", Side: "both"},
		{Kind: cluster.KindApp, ID: "roundcube", Pool: "tank", Side: SideCluster},
		{Kind: cluster.KindVM, ID: "web-kept-1", Pool: "tank", Side: SideLocal},
	} {
		if err := r.Validate(); err == nil {
			t.Errorf("%+v was accepted", r)
		}
	}
	if err := vmRef(SideLocal).Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := (Ref{Kind: cluster.KindApp, ID: "notes", Pool: "tank", Side: SideLocal}).dataset("disk0"); err == nil {
		t.Fatal("an app has disks")
	}
}

// The side picks the rules; the datasets' own marks decide.
func TestCheckSourceSides(t *testing.T) {
	f := newFake()
	f.add("tank", "filesystem")
	f.add("tank/vms", "filesystem")
	f.add("tank/vms/web", "filesystem", "org.hardyos:vm", "web", "org.hardyos:role", "cluster")
	f.add("tank/vms/web/disk0", "volume", "org.hardyos:vm", "web", "org.hardyos:role", "cluster")
	r := &Root{Runner: f}
	ctx := context.Background()
	if _, err := r.checkSource(ctx, vmRef(SideLocal)); err == nil {
		t.Fatal("cluster storage was taken for this server's own")
	}
	if _, err := r.checkSource(ctx, vmRef(SideCluster)); err != nil {
		t.Fatal(err)
	}
	// A dataset that isn't one of its disks stops it.
	f.add("tank/vms/web/extra", "filesystem")
	if _, err := r.checkSource(ctx, vmRef(SideCluster)); err == nil {
		t.Fatal("an unexpected dataset below a VM was sent along")
	}
	delete(f.ds, "tank/vms/web/extra")
	// Another VM's cluster storage under this name.
	f.ds["tank/vms/web"]["org.hardyos:vm"] = "other"
	if _, err := r.checkSource(ctx, vmRef(SideCluster)); err == nil {
		t.Fatal("another VM's storage was accepted")
	}
}

// Receives land only in the conversion's own folder, marked as the
// workload's; disks come after the state folder.
func TestRecvRules(t *testing.T) {
	f := newFake()
	f.add("tank", "filesystem")
	r := &Root{Runner: f, Starter: noStart{}}
	ctx := context.Background()
	ref := vmRef(SideCluster)
	if _, _, err := r.Recv(ctx, RecvArgs{Ref: ref, Conv: "abcdefgh12", Child: "disk0", Label: "s1"}); err == nil {
		t.Fatal("a disk was received before the state folder")
	}
	if _, _, err := r.Recv(ctx, RecvArgs{Ref: ref, Conv: "x", Label: "s1"}); err == nil {
		t.Fatal("a bad conversion id was accepted")
	}
	// Another workload's conversion folder.
	f.add("tank/hardyos-ha-incoming", "filesystem")
	f.add("tank/hardyos-ha-incoming/abcdefgh12", "filesystem", PropIncoming, "vm:other")
	if _, _, err := r.Recv(ctx, RecvArgs{Ref: ref, Conv: "abcdefgh12", Label: "s1"}); err == nil {
		t.Fatal("received into another workload's conversion")
	}
}

type noStart struct{}

func (noStart) Start(string, []string, io.Reader, io.Writer, io.Writer) (replica.Proc, error) {
	return nil, errors.New("nothing is run here")
}

// Parking needs the name typed and, on the storage server, nothing mapped;
// a parked copy is no longer marked as the workload's.
func TestPark(t *testing.T) {
	f := newFake()
	f.add("tank", "filesystem")
	f.add("tank/vms", "filesystem")
	f.add("tank/vms/web", "filesystem", "org.hardyos:vm", "web", "org.hardyos:role", "cluster")
	f.add("tank/vms/web/disk0", "volume", "org.hardyos:vm", "web", "org.hardyos:role", "cluster")
	busy := true
	r := &Root{Runner: f, Busy: func(context.Context, cluster.WorkloadKind, string, string) (bool, error) { return busy, nil },
		Now: func() time.Time { return time.Unix(1000, 0) }}
	ctx := context.Background()
	ref := vmRef(SideCluster)
	if _, err := r.Park(ctx, ParkArgs{Ref: ref, Confirm: "nope"}); err == nil {
		t.Fatal("parked without the name typed")
	}
	if _, err := r.Park(ctx, ParkArgs{Ref: ref, Confirm: "web"}); !errors.Is(err, ErrBusy) {
		t.Fatalf("parked while mapped: %v", err)
	}
	busy = false
	pr, err := r.Park(ctx, ParkArgs{Ref: ref, Confirm: "web", KeepUntil: 5000})
	if err != nil {
		t.Fatal(err)
	}
	ds := "tank/" + ParkedDir + "/" + pr.Name
	if pr.Name != "vm-web-1000" || f.ds[ds][PropParked] != "vm:web:cluster" || f.ds[ds][PropKeepUntil] != "5000" {
		t.Fatalf("parked %s: %+v", pr.Name, f.ds[ds])
	}
	for _, n := range []string{ds, ds + "/disk0"} {
		if f.get(n, "org.hardyos:role", true) == "cluster" || f.ds[n]["org.hardyos:vm"] != "" {
			t.Fatalf("%s is still marked: %+v", n, f.ds[n])
		}
	}
	if _, there := f.ds["tank/vms/web"]; there {
		t.Fatal("the workload's dataset is still there")
	}
	l, err := r.ParkedList(ctx)
	if err != nil || len(l) != 1 || l[0].ID != "web" || l[0].Side != SideCluster || l[0].KeepUntil.Unix() != 5000 {
		t.Fatalf("parked list %+v %v", l, err)
	}
	if err := r.ParkedDestroy(ctx, ParkedDestroyArgs{Pool: "tank", Name: pr.Name, Confirm: "other"}); err == nil {
		t.Fatal("destroyed with another name typed")
	}
	// Put back: marked as cluster storage again.
	if err := r.Unpark(ctx, UnparkArgs{Ref: ref, Name: pr.Name}); err != nil {
		t.Fatal(err)
	}
	if f.ds["tank/vms/web"]["org.hardyos:role"] != "cluster" || f.ds["tank/vms/web/disk0"]["volmode"] != "dev" || f.ds["tank/vms/web"][PropParked] != "" {
		t.Fatalf("put back: %+v %+v", f.ds["tank/vms/web"], f.ds["tank/vms/web/disk0"])
	}
}

// Adopting needs the conversion's own complete copy and never replaces a
// dataset.
func TestAdoptRules(t *testing.T) {
	f := newFake()
	f.add("tank", "filesystem")
	f.add("tank/vms", "filesystem")
	f.add("tank/hardyos-ha-incoming", "filesystem")
	f.add("tank/hardyos-ha-incoming/abcdefgh12", "filesystem", PropIncoming, "vm:web")
	f.add("tank/hardyos-ha-incoming/abcdefgh12/vm-web", "filesystem")
	f.add("tank/hardyos-ha-incoming/abcdefgh12/vm-web/disk0", "volume")
	r := &Root{Runner: f}
	ctx := context.Background()
	ref := vmRef(SideCluster)
	const cid = cluster.ClusterID("hchatestclusteraaaaaaaaaaaa")
	f.add("tank/vms/web", "filesystem")
	if _, err := r.Adopt(ctx, AdoptArgs{Ref: ref, Conv: "abcdefgh12", Cluster: cid}); err == nil {
		t.Fatal("adopted over an existing dataset")
	}
	delete(f.ds, "tank/vms/web")
	res, err := r.Adopt(ctx, AdoptArgs{Ref: ref, Conv: "abcdefgh12", Cluster: cid})
	if err != nil {
		t.Fatal(err)
	}
	if res.Dataset != "tank/vms/web" || len(res.Volumes) != 1 || res.Volumes[0].WWN == "" {
		t.Fatalf("adopted %+v", res)
	}
	p := f.ds["tank/vms/web"]
	if p["org.hardyos:role"] != "cluster" || p["org.hardyos:vm"] != "web" || p["exec"] != "off" || f.ds["tank/vms/web/disk0"]["volmode"] != "dev" {
		t.Fatalf("adopted marks %+v %+v", p, f.ds["tank/vms/web/disk0"])
	}
	if _, there := f.ds["tank/hardyos-ha-incoming/abcdefgh12"]; there {
		t.Fatal("the incoming folder stayed")
	}
	// Once adopted, Abort has nothing of it to remove.
	if err := r.Abort(ctx, AbortArgs{Ref: ref, Conv: "abcdefgh12"}); err != nil {
		t.Fatal(err)
	}
	if _, there := f.ds["tank/vms/web"]; !there {
		t.Fatal("abandoning a conversion removed adopted storage")
	}
}
