package storagesvc

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/san"
	"github.com/hardyos/hardyos/daemon/internal/cluster/sanclient"
)

// Peer API paths (under cluster.PeerPathPrefix).
//
// On the storage node: provision/vm, provision/app, resize, destroy,
// snapshots, snapshot, snapshot/delete, rollback, mode, share, health,
// status, exports, chap (a node's own CHAP secrets: only that node gets
// them), writers (who last wrote a granted volume: only its holder asks)
// and rejoin (a fenced node's own signed rejoin statement).
// On compute nodes (only the storage node may call): freeze, thaw, dump,
// detach; status from any member.
//
// The person behind a request is only ever taken from a verified
// assertion (auth.go), never from the body.

func peerPattern(path string) string { return "POST " + cluster.PeerPathPrefix + "storage/" + path }

// RegisterPeer adds the storage handlers to the peer API (part A serves
// it to current members only).
func (s *Service) RegisterPeer(mux cluster.PeerMux) {
	serve := func(caller func(*http.Request) (cluster.Node, bool), fn func(r *http.Request, caller cluster.Node, q asked, body []byte) (any, error)) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, ok := caller(r)
			if !ok {
				writePeerError(w, http.StatusForbidden, errors.New("not a member"))
				return
			}
			body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			if err != nil {
				writePeerError(w, http.StatusBadRequest, err)
				return
			}
			q, err := s.verifyAsker(r, c, body)
			if err != nil {
				writePeerError(w, statusOf(err), err)
				return
			}
			out, err := fn(r, c, q, body)
			if err != nil {
				writePeerError(w, statusOf(err), err)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(out)
		})
	}
	h := func(path string, fn func(r *http.Request, caller cluster.Node, q asked, body []byte) (any, error)) {
		mux.Handle(peerPattern(path), serve(mux.Caller, fn))
	}
	decode := func(b []byte, v any) error {
		if err := json.Unmarshal(b, v); err != nil {
			return &badRequest{err}
		}
		return nil
	}
	// storage wraps a storage node handler: only the storage node serves
	// it (never relayed on by a compute node).
	storage := func(fn func(r *http.Request, c cluster.Node, q asked, b []byte) (any, error)) func(r *http.Request, c cluster.Node, q asked, b []byte) (any, error) {
		return func(r *http.Request, c cluster.Node, q asked, b []byte) (any, error) {
			me, _, err := s.self()
			if err != nil {
				return nil, err
			}
			if me.Role != cluster.RoleStorage {
				return nil, errors.New("this isn't the storage server")
			}
			return fn(r, c, q, b)
		}
	}
	h("provision/vm", storage(func(r *http.Request, c cluster.Node, q asked, b []byte) (any, error) {
		var p provisionVMReq
		if err := decode(b, &p); err != nil {
			return nil, err
		}
		return s.ProvisionVM(r.Context(), p.Request, q.Actor)
	}))
	h("provision/app", storage(func(r *http.Request, c cluster.Node, q asked, b []byte) (any, error) {
		var p provisionAppReq
		if err := decode(b, &p); err != nil {
			return nil, err
		}
		return s.ProvisionApp(r.Context(), p.Request, q.Actor)
	}))
	h("resize", storage(func(r *http.Request, c cluster.Node, q asked, b []byte) (any, error) {
		var p resizeReq
		if err := decode(b, &p); err != nil {
			return nil, err
		}
		if err := needAdmin(q, "resizing a disk"); err != nil {
			return nil, err
		}
		return ok(s.ResizeDisk(r.Context(), p.Workload, p.Disk, p.SizeGB, q.Actor))
	}))
	h("destroy", storage(func(r *http.Request, c cluster.Node, q asked, b []byte) (any, error) {
		var p destroyReq
		if err := decode(b, &p); err != nil {
			return nil, err
		}
		if err := needAdmin(q, "destroying a workload's storage"); err != nil {
			return nil, err
		}
		return ok(s.Destroy(r.Context(), p.Workload, p.Confirm, q.Actor))
	}))
	h("snapshots", storage(func(r *http.Request, c cluster.Node, q asked, b []byte) (any, error) {
		var p snapReq
		if err := decode(b, &p); err != nil {
			return nil, err
		}
		return s.Snapshots(r.Context(), p.Workload)
	}))
	h("snapshot", storage(func(r *http.Request, c cluster.Node, q asked, b []byte) (any, error) {
		var p snapReq
		if err := decode(b, &p); err != nil {
			return nil, err
		}
		if !q.Admin {
			// A server's own request: only for a workload it owns, and
			// not too often (M4).
			if err := s.ownedBy(p.Workload, c.ID); err != nil {
				return nil, err
			}
			if err := s.ownerSnapshotAllowed(p.Workload, time.Now()); err != nil {
				return nil, err
			}
		}
		return s.Snapshot(r.Context(), p.Workload, p.Name, q.Actor)
	}))
	h("snapshot/delete", storage(func(r *http.Request, c cluster.Node, q asked, b []byte) (any, error) {
		var p snapReq
		if err := decode(b, &p); err != nil {
			return nil, err
		}
		if err := needAdmin(q, "deleting a snapshot"); err != nil {
			return nil, err
		}
		return ok(s.DeleteSnapshot(r.Context(), p.Workload, p.Name, p.Confirm, q.Actor))
	}))
	h("rollback", storage(func(r *http.Request, c cluster.Node, q asked, b []byte) (any, error) {
		var p snapReq
		if err := decode(b, &p); err != nil {
			return nil, err
		}
		if err := needAdmin(q, "rolling back"); err != nil {
			return nil, err
		}
		return ok(s.Rollback(r.Context(), p.Workload, p.Name, p.Confirm, q.Actor))
	}))
	h("mode", storage(func(r *http.Request, c cluster.Node, q asked, b []byte) (any, error) {
		var p ModeRequest
		if err := decode(b, &p); err != nil {
			return nil, err
		}
		if err := needAdmin(q, "moving an app's data"); err != nil {
			return nil, err
		}
		p.Actor = q.Actor
		return s.SwitchAppMode(r.Context(), p)
	}))
	h("share", storage(func(r *http.Request, c cluster.Node, q asked, b []byte) (any, error) {
		var p ShareRequest
		if err := decode(b, &p); err != nil {
			return nil, err
		}
		if err := needAdmin(q, "putting a shared folder in or out of the cluster"); err != nil {
			return nil, err
		}
		p.Actor = q.Actor
		return ok(s.SetShareCluster(r.Context(), p))
	}))
	h("health", func(r *http.Request, c cluster.Node, q asked, b []byte) (any, error) {
		return s.Health(r.Context())
	})
	h("status", func(r *http.Request, c cluster.Node, q asked, b []byte) (any, error) {
		return s.LocalStatus(r.Context())
	})
	h("exports", func(r *http.Request, c cluster.Node, q asked, b []byte) (any, error) {
		return s.Exports(r.Context())
	})
	// A compute node's own CHAP secrets, to that node only.
	h("chap", storage(func(r *http.Request, c cluster.Node, q asked, b []byte) (any, error) {
		if c.Role != cluster.RoleCompute || c.State != cluster.NodeActive && c.State != cluster.NodeJoining && c.State != cluster.NodeMaintenance {
			return nil, &forbidden{errors.New("only an active compute server gets its CHAP secrets")}
		}
		var sec san.Secrets
		if err := s.Priv.Call(r.Context(), san.OpCHAP, san.CHAPArgs{Node: c.ID}, &sec); err != nil {
			return nil, err
		}
		s.audit(r.Context(), cluster.Actor{Kind: "system", Name: "storage agent", Via: c.ID}, "cluster.storage.chap.issue", string(c.ID), nil)
		return sec, nil
	}))
	// Who wrote a granted block volume before: only a node the volume is
	// granted to asks (H5).
	h("writers", storage(func(r *http.Request, c cluster.Node, q asked, b []byte) (any, error) {
		var p writersReq
		if err := decode(b, &p); err != nil {
			return nil, err
		}
		return s.writers(r.Context(), c.ID, p.Workload)
	}))
	// A fenced node's own signed rejoin statement (H3). Fenced nodes may
	// send it; root checks the signature with the key it pinned.
	mux.AllowFenced(peerPattern("rejoin"), serve(mux.Caller, storage(func(r *http.Request, c cluster.Node, q asked, b []byte) (any, error) {
		var p san.RejoinStatement
		if err := decode(b, &p); err != nil {
			return nil, err
		}
		if p.Node != c.ID {
			return nil, &forbidden{errors.New("a server sends only its own rejoin")}
		}
		s.rejoinMu.Lock()
		if s.rejoins == nil {
			s.rejoins = map[cluster.NodeID]san.RejoinStatement{}
		}
		s.rejoins[c.ID] = p
		s.rejoinMu.Unlock()
		if s.reconcile != nil {
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				_ = s.reconcile(ctx)
			}()
		}
		return map[string]bool{"received": true}, nil
	})))
	// Compute side: asked by the storage node.
	h("freeze", func(r *http.Request, c cluster.Node, q asked, b []byte) (any, error) {
		var p freezeReq
		if err := decode(b, &p); err != nil {
			return nil, err
		}
		fr, err := s.ownerFreeze(r.Context(), c, p.VM)
		return freezeResp{Frozen: fr}, err
	})
	h("thaw", func(r *http.Request, c cluster.Node, q asked, b []byte) (any, error) {
		var p freezeReq
		if err := decode(b, &p); err != nil {
			return nil, err
		}
		return ok(s.ownerThaw(r.Context(), c, p.VM))
	})
	h("dump", func(r *http.Request, c cluster.Node, q asked, b []byte) (any, error) {
		var p dumpReq
		if err := decode(b, &p); err != nil {
			return nil, err
		}
		return ok(s.ownerDump(r.Context(), c, p.App))
	})
	h("detach", func(r *http.Request, c cluster.Node, q asked, b []byte) (any, error) {
		var p detachReq
		if err := decode(b, &p); err != nil {
			return nil, err
		}
		return ok(s.ownerDetach(r.Context(), c, p.Workload))
	})
}

// ownedBy checks that the applied state places a workload on node.
func (s *Service) ownedBy(w cluster.WorkloadRef, node cluster.NodeID) error {
	_, snap, err := s.self()
	if err != nil {
		return err
	}
	if p := snap.Placements[w]; p == nil || p.Owner != node {
		return &forbidden{errors.New("a server may only ask for snapshots of its own workloads")}
	}
	return nil
}

type writersReq struct {
	Workload cluster.WorkloadRef `json:"workload"`
}

// VolumeWriters says, per WWN, whether anyone but the asking node wrote a
// volume in its last two holder sets, and the holders' sequence.
type VolumeWriters map[string]sanclient.WriterInfo

// writers answers a holder's question about its granted volumes.
func (s *Service) writers(ctx context.Context, caller cluster.NodeID, w cluster.WorkloadRef) (VolumeWriters, error) {
	_, snap, err := s.self()
	if err != nil {
		return nil, err
	}
	g := snap.Grants[w]
	p := snap.Placements[w]
	if g == nil || p == nil || !slices.Contains(g.Nodes, caller) {
		return nil, &forbidden{errors.New("only a server the volume is granted to asks who wrote it")}
	}
	var st san.Status
	if err := s.Priv.Call(ctx, san.OpStatus, nil, &st); err != nil {
		return nil, err
	}
	out := VolumeWriters{}
	for _, v := range p.Storage.Volumes {
		h := st.Holders[san.BackstoreName(w, v.Disk)]
		wi := sanclient.WriterInfo{Known: h != nil, OthersWrote: h.OthersWrote(caller)}
		if h != nil {
			wi.Seq = h.Seq
		}
		out[v.WWN] = wi
	}
	return out, nil
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
	err := s.onStorage(ctx, "storage/exports", struct{}{}, &out, cluster.Actor{}, func(*cluster.Snapshot, cluster.Node) error {
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
