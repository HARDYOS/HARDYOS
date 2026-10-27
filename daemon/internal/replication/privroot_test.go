package replication

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/replica"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// echoStarter stands in for zfs: a send writes "STREAM", a receive keeps
// what it read.
type echoStarter struct {
	mu   sync.Mutex
	got  []byte
	runs []string
}

type doneProc struct{ ch chan struct{} }

func (p doneProc) Wait() error { <-p.ch; return nil }
func (p doneProc) Kill()       {}

func (e *echoStarter) Start(name string, args []string, stdin io.Reader, stdout, stderr io.Writer) (replica.Proc, error) {
	e.mu.Lock()
	e.runs = append(e.runs, name+" "+strings.Join(args, " "))
	e.mu.Unlock()
	if f, ok := stdout.(*os.File); ok {
		fd, err := syscall.Dup(int(f.Fd()))
		if err != nil {
			return nil, err
		}
		stdout = os.NewFile(uintptr(fd), "stdout")
	}
	p := doneProc{ch: make(chan struct{})}
	go func() {
		defer close(p.ch)
		if stdin != nil {
			b, _ := io.ReadAll(stdin)
			e.mu.Lock()
			e.got = b
			e.mu.Unlock()
		}
		if f, ok := stdout.(*os.File); ok {
			_, _ = f.WriteString("STREAM")
			f.Close()
		}
	}()
	return p, nil
}

type oneItem struct{}

func (oneItem) List(context.Context) ([]replica.LocalItem, error) {
	return []replica.LocalItem{{Kind: replica.KindShare, ID: "media", Name: "Media", Pool: "tank", Dataset: "tank/shares/media"}}, nil
}

func (oneItem) Resolve(_ context.Context, kind, id string) (string, error) {
	if kind == replica.KindShare && id == "media" {
		return "tank/shares/media", nil
	}
	return "", replica.ErrNotFound
}

// TestPrivRootOverTheSocket runs the replication operations through a real
// hardyd-priv socket: streams arrive as file descriptors both ways, the
// receive is checked before "zfs" starts, bad names are refused.
func TestPrivRootOverTheSocket(t *testing.T) {
	label := "hardyos-repl-abc123-20261027T101500Z"
	f := &sysexec.Fake{}
	f.On("zfs list -H -o type tank/shares/media@"+label, "snapshot\n")
	f.On("zfs send -n -P -L -e -c tank/shares/media@"+label, "size\t6\n")
	f.On("zfs list -H -o name tank", "tank\n")
	f.On("zfs list -H -o type tank/replicas", "filesystem\n")
	f.On("zfs get -H -p -o value org.hardyos:role tank/replicas", "replicas\n")
	f.On("zfs list -H -o type tank/replicas/a1b2c3d4", "filesystem\n")
	f.On("zfs get -H -p -o value org.hardyos:replica tank/replicas/a1b2c3d4", "a1b2c3d4\n")
	f.On("zfs get -H -p -o value quota tank/replicas/a1b2c3d4", "0\n")
	f.On("zfs list -H -o type tank/replicas/a1b2c3d4/share", "filesystem\n")
	st := &echoStarter{}
	m := &replica.Manager{Runner: f, Starter: st, Items: oneItem{}}

	s := &priv.Server{AllowedUIDs: []uint32{uint32(os.Getuid())}}
	priv.RegisterReplication(s, m)
	sock := filepath.Join(t.TempDir(), "priv.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = s.Serve(ctx, ln); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	for _, op := range s.Ops() {
		if !strings.HasPrefix(op, "repl.") {
			t.Errorf("unexpected op %s", op)
		}
	}
	root := &PrivRoot{Priv: priv.NewClient(sock)}

	items, err := root.Items(ctx)
	if err != nil || len(items) != 1 {
		t.Fatal(items, err)
	}
	ss, r, err := root.Send(ctx, replica.SendArgs{Task: "abc123", Kind: replica.KindShare, ID: "media", Snapshot: label})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(r)
	r.Close()
	if string(b) != "STREAM" || ss.Estimate != 6 {
		t.Fatalf("%q %+v", b, ss)
	}
	waitOK(t, root, ss.Stream)

	tg := replica.Target{Pool: "tank", Source: "a1b2c3d4", Kind: replica.KindShare, Item: "media"}
	rs, w, err := root.Recv(ctx, replica.RecvArgs{Target: tg, Task: "abc123", Snapshot: label})
	if err != nil {
		t.Fatal(err)
	}
	rec := make([]byte, replica.BeginRecordSize)
	binary.LittleEndian.PutUint64(rec[8:], 0x2F5bacbac)
	binary.LittleEndian.PutUint64(rec[16:], 1)
	binary.LittleEndian.PutUint32(rec[32:], replica.ObjsetFilesystem)
	copy(rec[56:], "tank/shares/media@"+label)
	_, _ = w.Write(append(rec, "data"...))
	w.Close()
	waitOK(t, root, rs.Stream)
	st.mu.Lock()
	if len(st.got) != len(rec)+4 || !strings.HasPrefix(st.runs[len(st.runs)-1], "zfs receive -u -s") {
		t.Fatalf("%d %v", len(st.got), st.runs)
	}
	st.mu.Unlock()

	// Names outside the confined path never reach root's commands.
	bad := tg
	bad.Item = "../../etc"
	_, _, err = root.Recv(ctx, replica.RecvArgs{Target: bad, Task: "abc123", Snapshot: label})
	var pe *priv.Error
	if !errors.As(err, &pe) || pe.Code != priv.CodeBadArgs {
		t.Fatalf("bad target: %v", err)
	}
	if _, err := root.Stream(ctx, "nope"); !errors.As(err, &pe) || pe.Code != priv.CodeNotFound {
		t.Fatalf("unknown stream: %v", err)
	}
	// Unknown fields are refused too (no smuggled options).
	if err := root.Priv.Call(ctx, priv.OpReplRecvState, map[string]any{"pool": "tank", "source": "a1b2c3d4", "kind": "share", "item": "media", "dataset": "/"}, nil); err == nil {
		t.Fatal("unknown argument accepted")
	}
}

func waitOK(t *testing.T, root Root, id string) {
	t.Helper()
	for i := 0; i < 200; i++ {
		st, err := root.Stream(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		if st.Done {
			if !st.OK {
				t.Fatal(st.Error)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("stream didn't finish")
}
