package storagesvc

// Who asked (security review H1, decision 375). A storage peer request
// names its person only through an assertion (cluster.Assertion, the
// relay's signed statement) that the calling node signs with its cluster
// key for this very request; the body's actor is ignored. Without one the
// request is the calling node's own (a system actor), which may provision
// and may snapshot only workloads it owns; destroying, rolling back,
// deleting snapshots, resizing, switching an app's data mode and putting
// shared folders in or out of the cluster need an administrator's
// assertion. Whether a compromised member could still sign such an
// assertion itself (step-up re-authentication on the storage node) is
// pending the owner's decision on member isolation
// (docs/plans/cluster.md 8.1).

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
)

// Signer is what signs for this node: the running cluster core.
type Signer interface {
	AssertFor(f *cluster.Forward, bodySum []byte) (string, error)
	Identity() *cluster.Identity
}

// coreSource is the membership that knows the running core (member.Live).
type coreSource interface{ Core() *cluster.Core }

// core is the running cluster core: its key signs assertions and rejoin
// statements.
func (s *Service) core() Signer {
	if s.Signer != nil {
		return s.Signer()
	}
	if cs, ok := s.M.(coreSource); ok {
		if c := cs.Core(); c != nil {
			return c
		}
	}
	return nil
}

// person reports whether an actor is a person (not HardyOS itself).
func person(a cluster.Actor) bool { return a.Kind == "local" || a.Kind == "domain" }

// callStorage sends a request to the storage node's peer API. A person's
// request carries an assertion the storage node checks; the actor in the
// body is informational only.
func (s *Service) callStorage(ctx context.Context, node cluster.NodeID, path string, in, out any, actor cluster.Actor) error {
	if s.Peers == nil {
		return cluster.ErrStorageUnavailable
	}
	if !person(actor) {
		return s.Peers.Call(ctx, node, "POST", path, in, out)
	}
	c := s.core()
	if c == nil {
		return errors.New("the cluster core isn't running, so the request can't be signed")
	}
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	full := cluster.PeerPathPrefix + path
	sum := sha256.Sum256(body)
	jws, err := c.AssertFor(&cluster.Forward{Node: node, Principal: cluster.Principal{Kind: actor.Kind, Name: actor.Name, SID: actor.SID, Admin: true},
		Method: http.MethodPost, Path: full}, sum[:])
	if err != nil {
		return fmt.Errorf("signing the request: %w", err)
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+string(node)+full, bytes.NewReader(body))
	if err != nil {
		return err
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set(cluster.AssertionHeader, jws)
	resp, err := s.Peers.Do(ctx, node, r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		var we struct {
			Message string `json:"message"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&we)
		if we.Message == "" {
			we.Message = fmt.Sprintf("answered %d", resp.StatusCode)
		}
		return &cluster.PeerError{Node: node, Status: resp.StatusCode, Message: we.Message}
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(out)
}

// asked is who asked for a peer request on the storage node.
type asked struct {
	Actor cluster.Actor
	// Admin: an administrator's assertion, verified.
	Admin bool
}

// verifyAsker checks a peer request's assertion, if any: issued by the
// calling node (its key from the state), for this node, fresh, unseen and
// bound to this method, path and body.
func (s *Service) verifyAsker(r *http.Request, caller cluster.Node, body []byte) (asked, error) {
	sys := asked{Actor: cluster.Actor{Kind: "system", Name: "server " + string(caller.ID), Via: caller.ID}}
	jws := r.Header.Get(cluster.AssertionHeader)
	if jws == "" {
		return sys, nil
	}
	me, _, err := s.self()
	if err != nil {
		return sys, err
	}
	s.nonceOnce.Do(func() { s.nonces = &cluster.NonceCache{} })
	a, err := cluster.VerifyAssertion(jws, cluster.AssertionCheck{Issuer: caller.ID, IssuerKey: caller.PublicKey, Audience: me.ID,
		Request: cluster.RequestHash(r.Method, r.URL.Path, r.URL.RawQuery, body), Now: time.Now(), Nonces: s.nonces})
	if err != nil {
		return sys, &forbidden{err}
	}
	return asked{Actor: cluster.Actor{Kind: a.Subject.Kind, Name: a.Subject.Name, SID: a.Subject.SID, Via: caller.ID}, Admin: a.Subject.Admin}, nil
}

// needAdmin refuses a request that isn't an administrator's.
func needAdmin(q asked, what string) error {
	if !q.Admin {
		return &forbidden{fmt.Errorf("%s needs an administrator's signed request, not a server's own", what)}
	}
	return nil
}

// Owner snapshot limits (M4): a server may ask for snapshots of its own
// workloads at most this often.
const (
	OwnerSnapshotGap     = time.Minute
	OwnerSnapshotsPerDay = 48
)

// ownerSnapshotAllowed rate-limits a server's own snapshot requests.
func (s *Service) ownerSnapshotAllowed(w cluster.WorkloadRef, now time.Time) error {
	s.snapMu.Lock()
	defer s.snapMu.Unlock()
	if s.snapTimes == nil {
		s.snapTimes = map[cluster.WorkloadRef][]time.Time{}
	}
	l := slices.DeleteFunc(s.snapTimes[w], func(t time.Time) bool { return now.Sub(t) > 24*time.Hour })
	if len(l) > 0 && now.Sub(l[len(l)-1]) < OwnerSnapshotGap {
		s.snapTimes[w] = l
		return &forbidden{fmt.Errorf("%s %s was snapshotted less than %s ago", w.Kind, w.ID, OwnerSnapshotGap)}
	}
	if len(l) >= OwnerSnapshotsPerDay {
		s.snapTimes[w] = l
		return &forbidden{fmt.Errorf("%s %s had %d snapshots asked for by its server today", w.Kind, w.ID, len(l))}
	}
	s.snapTimes[w] = append(l, now)
	return nil
}

// authState is the service's request-checking state.
type authState struct {
	nonceOnce sync.Once
	nonces    *cluster.NonceCache
	snapMu    sync.Mutex
	snapTimes map[cluster.WorkloadRef][]time.Time
}
