package storagesvc

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/san"
	"github.com/hardyos/hardyos/daemon/internal/cluster/sanclient"
)

// Peer API paths (under cluster.PeerPathPrefix).
//
// On the storage node: provision/vm, provision/app, resize, destroy,
// snapshots, snapshot, snapshot/delete, rollback, mode, health, status and
// chap (a node's own CHAP secrets: only that node gets them).
// On compute nodes (only the storage node may call): freeze, thaw, dump,
// detach; status from any member.

func peerPattern(path string) string { return "POST " + cluster.PeerPathPrefix + "storage/" + path }

// RegisterPeer adds the storage handlers to the peer API (part A serves
// it to current members only).
func (s *Service) RegisterPeer(mux cluster.PeerMux) {
	h := func(path string, fn func(r *http.Request, caller cluster.Node, body []byte) (any, error)) {
		mux.Handle(peerPattern(path), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			caller, ok := mux.Caller(r)
			if !ok {
				writePeerError(w, http.StatusForbidden, errors.New("not a member"))
				return
			}
			body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			if err != nil {
				writePeerError(w, http.StatusBadRequest, err)
				return
			}
			out, err := fn(r, caller, body)
			if err != nil {
				writePeerError(w, statusOf(err), err)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(out)
		}))
	}
	decode := func(b []byte, v any) error {
		if err := json.Unmarshal(b, v); err != nil {
			return &badRequest{err}
		}
		return nil
	}
	// The actor of a forwarded request is the person on the calling node;
	// the node part is always the caller itself.
	via := func(a cluster.Actor, caller cluster.Node) cluster.Actor {
		a.Via = caller.ID
		if a.Kind != "local" && a.Kind != "domain" {
			a.Kind = "system"
		}
		return a
	}
	h("provision/vm", func(r *http.Request, c cluster.Node, b []byte) (any, error) {
		var q provisionVMReq
		if err := decode(b, &q); err != nil {
			return nil, err
		}
		return s.ProvisionVM(r.Context(), q.Request, via(q.Actor, c))
	})
	h("provision/app", func(r *http.Request, c cluster.Node, b []byte) (any, error) {
		var q provisionAppReq
		if err := decode(b, &q); err != nil {
			return nil, err
		}
		return s.ProvisionApp(r.Context(), q.Request, via(q.Actor, c))
	})
	h("resize", func(r *http.Request, c cluster.Node, b []byte) (any, error) {
		var q resizeReq
		if err := decode(b, &q); err != nil {
			return nil, err
		}
		return ok(s.ResizeDisk(r.Context(), q.Workload, q.Disk, q.SizeGB, via(q.Actor, c)))
	})
	h("destroy", func(r *http.Request, c cluster.Node, b []byte) (any, error) {
		var q destroyReq
		if err := decode(b, &q); err != nil {
			return nil, err
		}
		return ok(s.Destroy(r.Context(), q.Workload, q.Confirm, via(q.Actor, c)))
	})
	h("snapshots", func(r *http.Request, c cluster.Node, b []byte) (any, error) {
		var q snapReq
		if err := decode(b, &q); err != nil {
			return nil, err
		}
		return s.Snapshots(r.Context(), q.Workload)
	})
	h("snapshot", func(r *http.Request, c cluster.Node, b []byte) (any, error) {
		var q snapReq
		if err := decode(b, &q); err != nil {
			return nil, err
		}
		return s.Snapshot(r.Context(), q.Workload, q.Name, via(q.Actor, c))
	})
	h("snapshot/delete", func(r *http.Request, c cluster.Node, b []byte) (any, error) {
		var q snapReq
		if err := decode(b, &q); err != nil {
			return nil, err
		}
		return ok(s.DeleteSnapshot(r.Context(), q.Workload, q.Name, q.Confirm, via(q.Actor, c)))
	})
	h("rollback", func(r *http.Request, c cluster.Node, b []byte) (any, error) {
		var q snapReq
		if err := decode(b, &q); err != nil {
			return nil, err
		}
		return ok(s.Rollback(r.Context(), q.Workload, q.Name, q.Confirm, via(q.Actor, c)))
	})
	h("mode", func(r *http.Request, c cluster.Node, b []byte) (any, error) {
		var q ModeRequest
		if err := decode(b, &q); err != nil {
			return nil, err
		}
		q.Actor = via(q.Actor, c)
		return s.SwitchAppMode(r.Context(), q)
	})
	h("share", func(r *http.Request, c cluster.Node, b []byte) (any, error) {
		var q ShareRequest
		if err := decode(b, &q); err != nil {
			return nil, err
		}
		q.Actor = via(q.Actor, c)
		return ok(s.SetShareCluster(r.Context(), q))
	})
	h("health", func(r *http.Request, c cluster.Node, b []byte) (any, error) {
		return s.Health(r.Context())
	})
	h("status", func(r *http.Request, c cluster.Node, b []byte) (any, error) {
		return s.LocalStatus(r.Context())
	})
	h("exports", func(r *http.Request, c cluster.Node, b []byte) (any, error) {
		return s.Exports(r.Context())
	})
	// A compute node's own CHAP secrets, to that node only.
	h("chap", func(r *http.Request, c cluster.Node, b []byte) (any, error) {
		me, _, err := s.self()
		if err != nil {
			return nil, err
		}
		if me.Role != cluster.RoleStorage {
			return nil, errors.New("this isn't the storage server")
		}
		if c.Role != cluster.RoleCompute || c.State != cluster.NodeActive && c.State != cluster.NodeJoining && c.State != cluster.NodeMaintenance {
			return nil, &forbidden{errors.New("only an active compute server gets its CHAP secrets")}
		}
		var sec san.Secrets
		if err := s.Priv.Call(r.Context(), san.OpCHAP, san.CHAPArgs{Node: c.ID}, &sec); err != nil {
			return nil, err
		}
		s.audit(r.Context(), cluster.Actor{Kind: "system", Name: "storage agent", Via: c.ID}, "cluster.storage.chap.issue", string(c.ID), nil)
		return sec, nil
	})
	// Compute side: asked by the storage node.
	h("freeze", func(r *http.Request, c cluster.Node, b []byte) (any, error) {
		var q freezeReq
		if err := decode(b, &q); err != nil {
			return nil, err
		}
		fr, err := s.ownerFreeze(r.Context(), c, q.VM)
		return freezeResp{Frozen: fr}, err
	})
	h("thaw", func(r *http.Request, c cluster.Node, b []byte) (any, error) {
		var q freezeReq
		if err := decode(b, &q); err != nil {
			return nil, err
		}
		return ok(s.ownerThaw(r.Context(), c, q.VM))
	})
	h("dump", func(r *http.Request, c cluster.Node, b []byte) (any, error) {
		var q dumpReq
		if err := decode(b, &q); err != nil {
			return nil, err
		}
		return ok(s.ownerDump(r.Context(), c, q.App))
	})
	h("detach", func(r *http.Request, c cluster.Node, b []byte) (any, error) {
		var q detachReq
		if err := decode(b, &q); err != nil {
			return nil, err
		}
		return ok(s.ownerDetach(r.Context(), c, q.Workload))
	})
}

// ownerDetach lets go of a stopped workload's storage when the storage
// node is about to work on it offline.
func (s *Service) ownerDetach(ctx context.Context, caller cluster.Node, w cluster.WorkloadRef) error {
	if err := s.callerIsStorage(caller); err != nil {
		return &forbidden{err}
	}
	_, snap, err := s.self()
	if err != nil {
		return err
	}
	if p := snap.Placements[w]; p == nil || !stopped(p) {
		return errors.New("the workload isn't stopped")
	}
	return s.Priv.Call(ctx, sanclient.OpDetach, sanclient.DetachArgs{Workload: w}, nil)
}

// Exports reports the storage node's cluster exports (path -> clients).
func (s *Service) Exports(ctx context.Context) (*san.Status, error) {
	var out san.Status
	err := s.onStorage(ctx, "storage/exports", struct{}{}, &out, func(*cluster.Snapshot, cluster.Node) error {
		return s.Priv.Call(ctx, san.OpStatus, nil, &out)
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func ok(err error) (any, error) {
	if err != nil {
		return nil, err
	}
	return map[string]bool{"ok": true}, nil
}

type badRequest struct{ error }
type forbidden struct{ error }

func statusOf(err error) int {
	var br *badRequest
	var fb *forbidden
	switch {
	case errors.As(err, &br):
		return http.StatusBadRequest
	case errors.As(err, &fb):
		return http.StatusForbidden
	case errors.Is(err, cluster.ErrNoQuorum), errors.Is(err, cluster.ErrStaleGeneration):
		return http.StatusConflict
	case errors.Is(err, cluster.ErrNotOwner), errors.Is(err, cluster.ErrNotMember):
		return http.StatusNotFound
	}
	return http.StatusUnprocessableEntity
}

func writePeerError(w http.ResponseWriter, status int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"message": err.Error()})
}
