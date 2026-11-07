package priv

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/cluster/san"
	"github.com/hardyos/hardyos/daemon/internal/cluster/sanclient"
	"github.com/hardyos/hardyos/daemon/internal/nfs"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

func TestClusterStorageOpsAreNamedAndValidated(t *testing.T) {
	s := &Server{}
	fx := &sysexec.Fake{}
	dir := t.TempDir()
	RegisterSAN(s, &san.Root{Runner: fx, FS: san.NewFakeFS(), Dir: filepath.Join(dir, "state"), Sys: dir, NFS: &nfs.ClusterManager{Runner: fx, Root: dir}})
	RegisterSANClient(s, &sanclient.Client{Runner: fx, Sys: dir})
	ops := s.Ops()
	for _, op := range ops {
		if !strings.HasPrefix(op, "san.") && !strings.HasPrefix(op, "sanclient.") && op != "nfs.cluster.apply" {
			t.Errorf("unexpected op %s", op)
		}
		if strings.Contains(op, "exec") || strings.Contains(op, "command") || strings.Contains(op, "run") {
			t.Errorf("op %s looks like a generic command", op)
		}
	}
	for _, want := range []string{san.OpApply, san.OpFence, san.OpUnfence, san.OpFirewallApply, san.OpVolumeCreate, san.OpVolumeDestroy,
		san.OpDatasetCreate, san.OpDatasetDestroy, san.OpNFSClusterSet, sanclient.OpLogin, sanclient.OpLogout, sanclient.OpRescan,
		sanclient.OpNFSMount, sanclient.OpNFSUmount, sanclient.OpMultipathApply, sanclient.OpInitiatorSet, sanclient.OpStatus} {
		if !slices.Contains(ops, want) {
			t.Errorf("missing %s", want)
		}
	}
	call := func(op string, args string) error {
		s.mu.RLock()
		fn := s.ops[op]
		s.mu.RUnlock()
		_, err := fn(context.Background(), json.RawMessage(args))
		return err
	}
	for op, args := range map[string]string{
		san.OpFence:           `{"node":"c1","epoch":1}`,                              // no confirmation
		san.OpDatasetDestroy:  `{"kind":"vm","id":"web","pool":"tank","confirm":"x"}`, // wrong confirmation
		san.OpVolumeCreate:    `{"cluster":"abcdefghijklmnopqrstuvwxyz","kind":"vm","id":"web","pool":"tank","disk":"../x","sizeGB":1}`,
		san.OpApply:           `{"desired":{"cluster":"abcdefghijklmnopqrstuvwxyz"},"extra":1}`, // unknown field
		sanclient.OpNFSMount:  `{"server":"10.77.0.10","interface":"enp2s0","dataset":"tank/../etc","exportPath":"/etc"}`,
		sanclient.OpLogin:     `{"cluster":"abcdefghijklmnopqrstuvwxyz","node":"c1","portals":["10.77.0.10:3260"],"interface":"enp2s0","chap":{"user":"a","password":"short","mutualUser":"b","mutualPassword":"short2"}}`,
		sanclient.OpNFSUmount: `{"dataset":"/"}`,
		san.OpSnapshotRoll:    `{"kind":"vm","id":"web","pool":"tank","name":"s1","confirm":"s2"}`,
		sanclient.OpFreeze:    `{"vm":"--help"}`,
		san.OpFirewallApply:   `{"role":"storage","interface":"eth0","subnet":"0.0.0.0/0"}`,
	} {
		err := call(op, args)
		var pe *Error
		if !errors.As(err, &pe) || pe.Code != CodeBadArgs {
			t.Errorf("%s %s: %v", op, args, err)
		}
	}
	for _, l := range fx.Lines() {
		if strings.HasPrefix(l, "zfs destroy") || strings.HasPrefix(l, "mount") || strings.HasPrefix(l, "iscsiadm") {
			t.Errorf("a refused op ran %s", l)
		}
	}
}
