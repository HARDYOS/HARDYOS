package priv

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/hardyos/hardyos/daemon/internal/cluster/sanclient"
)

// A compute node's cluster storage operations (docs/plans/cluster.md
// section 6.1): the initiator name, iSCSI logins with CHAP secrets written
// into root-only node records (never a command line), rescans, NFS mounts
// under /mnt/hc only, multipath's allow list, attaching and detaching a
// workload's storage (the records the VM and app engines read), and the
// VM freeze and app dump the storage node forwards for its snapshots.

func sanclientErr(err error) error {
	var ve *sanclient.ValidationError
	if errors.As(err, &ve) {
		return Errorf(CodeBadArgs, "%v", err)
	}
	return err
}

// LogoutArgs is sanclient.iscsi.logout.
type LogoutArgs struct {
	sanclient.SessionArgs
	// Leave also removes the node records (leaving the cluster).
	Leave bool `json:"leave,omitempty"`
}

// RegisterSANClient adds the compute node's storage client operations.
func RegisterSANClient(s *Server, c *sanclient.Client) {
	s.Handle(sanclient.OpStatus, func(ctx context.Context, _ json.RawMessage) (any, error) {
		st, err := c.Status(ctx)
		return st, sanclientErr(err)
	})
	s.Handle(sanclient.OpInitiatorSet, typed(func(ctx context.Context, a sanclient.SessionArgs) (any, error) {
		return map[string]bool{"set": true}, sanclientErr(c.SetInitiator(ctx, a))
	}))
	s.Handle(sanclient.OpLogin, typed(func(ctx context.Context, a sanclient.LoginArgs) (any, error) {
		return map[string]bool{"loggedIn": true}, sanclientErr(c.Login(ctx, a))
	}))
	s.Handle(sanclient.OpLogout, typed(func(ctx context.Context, a LogoutArgs) (any, error) {
		return map[string]bool{"loggedOut": true}, sanclientErr(c.Logout(ctx, a.SessionArgs, a.Leave))
	}))
	s.Handle(sanclient.OpRescan, typed(func(ctx context.Context, a sanclient.SessionArgs) (any, error) {
		return map[string]bool{"rescanned": true}, sanclientErr(c.Rescan(ctx, a))
	}))
	s.Handle(sanclient.OpNFSMount, typed(func(ctx context.Context, a sanclient.MountArgs) (any, error) {
		mp, err := c.MountNFS(ctx, a)
		return map[string]string{"mountPath": mp}, sanclientErr(err)
	}))
	s.Handle(sanclient.OpNFSUmount, typed(func(ctx context.Context, a sanclient.UmountArgs) (any, error) {
		return map[string]bool{"unmounted": true}, sanclientErr(c.Umount(ctx, a))
	}))
	s.Handle(sanclient.OpMultipathApply, typed(func(ctx context.Context, a sanclient.MultipathArgs) (any, error) {
		return map[string]bool{"applied": true}, sanclientErr(c.ApplyMultipath(ctx, a))
	}))
	s.Handle(sanclient.OpAttach, typed(func(ctx context.Context, a sanclient.AttachArgs) (any, error) {
		rec, err := c.Attach(ctx, a)
		return rec, sanclientErr(err)
	}))
	s.Handle(sanclient.OpDetach, typed(func(ctx context.Context, a sanclient.DetachArgs) (any, error) {
		return map[string]bool{"detached": true}, sanclientErr(c.Detach(ctx, a))
	}))
	s.Handle(sanclient.OpFreeze, typed(func(ctx context.Context, a sanclient.FreezeArgs) (any, error) {
		ok, err := c.Freeze(ctx, a)
		return map[string]bool{"frozen": ok}, sanclientErr(err)
	}))
	s.Handle(sanclient.OpThaw, typed(func(ctx context.Context, a sanclient.FreezeArgs) (any, error) {
		return map[string]bool{"thawed": true}, sanclientErr(c.Thaw(ctx, a))
	}))
	s.Handle(sanclient.OpAppDump, typed(func(ctx context.Context, a sanclient.DumpArgs) (any, error) {
		ran, err := c.AppDump(ctx, a)
		return map[string]bool{"ran": ran}, sanclientErr(err)
	}))
	if s.QuietOps == nil {
		s.QuietOps = map[string]bool{}
	}
	s.QuietOps[sanclient.OpStatus] = true
}
