package publish

// Cluster apps (Phase 8 part C, docs/plans/cluster.md section 6.6,
// decision 358). An app on cluster storage runs on whichever compute
// server the cluster places it on; its NetBird service is named after the
// cluster, not the server ("hardyos-c-<cluster8>-app-<id>"), so the new
// owner's sync finds the same service and points it at itself, and the old
// owner leaves it alone. The app's publishing choice (mode, sign-in,
// groups, password) moves with the app over the peer channel.

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
)

var clusterIDRE = regexp.MustCompile(`^[a-z2-7]{8,32}$`)

// ClusterServicePrefix is the name prefix of a cluster's app services.
func ClusterServicePrefix(clusterID string) string {
	id := clusterID
	if len(id) > 8 {
		id = id[:8]
	}
	return "hardyos-c-" + id + "-"
}

// clusterServiceName is a cluster app's service name.
func clusterServiceName(clusterID, key string) string {
	return ClusterServicePrefix(clusterID) + "app-" + key[len("app:"):]
}

// handoff is what travels with an app to its new owner.
type handoff struct {
	Config ServiceConfig `json:"config"`
	// Set: the old owner had a choice of its own (else the new owner's
	// default applies).
	Set bool `json:"set"`
	// Secret is the password or PIN (point to point over the cluster's
	// mutual TLS; sealed again by the new owner).
	Secret *string `json:"secret,omitempty"`
}

// Handoff carries cluster apps' publishing between owners
// (moves.PublishHandoff).
type Handoff struct {
	Store *Store
	// Sync runs this server's publish sync (after an import).
	Sync func(ctx context.Context)
}

// Export returns app's publishing choice on this server.
func (h Handoff) Export(ctx context.Context, app string) (json.RawMessage, error) {
	rows, err := h.Store.rows(ctx)
	if err != nil {
		return nil, err
	}
	r := rows[AppKey(app)]
	out := handoff{}
	if r != nil && r.mode != "" {
		out.Set = true
		out.Config = r.cfg
		out.Config.Mode = r.mode
		if r.secret != "" {
			sec, err := h.Store.secretOf(r)
			if err != nil {
				return nil, err
			}
			out.Secret = &sec
		}
	}
	return json.Marshal(out)
}

// Import saves app's publishing choice from its old owner and syncs.
func (h Handoff) Import(ctx context.Context, app string, raw json.RawMessage) error {
	var in handoff
	if err := json.Unmarshal(raw, &in); err != nil {
		return err
	}
	if !in.Set {
		return nil
	}
	c := in.Config
	c.HasSecret, c.Default = false, false
	if err := ValidateConfig(c, in.Secret); err != nil {
		return errors.New("the app's publishing settings from its old server aren't valid: " + err.Error())
	}
	if err := h.Store.SetConfig(ctx, AppKey(app), c, in.Secret); err != nil {
		return err
	}
	if h.Sync != nil {
		h.Sync(ctx)
	}
	return nil
}

// validClusterID reports whether id may name a cluster's services.
func validClusterID(id string) bool { return clusterIDRE.MatchString(id) }
