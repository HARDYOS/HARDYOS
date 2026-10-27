// Package replica is the root side of replication between HardyOS servers
// (it runs inside hardyd-priv): replication snapshots of shared folders,
// apps and VMs, `zfs send` streams handed to hardyd, `zfs receive` of
// another server's streams into a confined part of a pool, pruning,
// browsing and restoring replicas.
//
// Nothing here trusts a name it's given: every dataset name is built from
// validated components (pool, source id, item kind and id, child), and a
// received stream is checked (its first record) before zfs sees it.
package replica

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/zfs"
)

// Item kinds that can be replicated.
const (
	KindShare = "share"
	KindApp   = "app"
	KindVM    = "vm"
)

// Kinds lists the item kinds in a fixed order.
var Kinds = []string{KindShare, KindApp, KindVM}

// SnapPrefix starts every replication snapshot's label:
// hardyos-repl-<task>-<YYYYMMDD>T<HHMMSS>Z (UTC). Only labels that parse
// exactly like that, for the task in question, are ever pruned.
const SnapPrefix = "hardyos-repl-"

const snapTimeFormat = "20060102T150405Z"

// ReplicasDataset is where a receiving server keeps every source's
// replicas on a pool: <pool>/replicas/<source>/<kind>/<id>[/<child>].
const ReplicasDataset = "replicas"

// Properties HardyOS sets on what it receives.
const (
	PropReplica  = "org.hardyos:replica"  // the source id, on every received dataset
	PropRole     = "org.hardyos:role"     // "replicas" on <pool>/replicas, "replica-source" below it
	PropRestored = "org.hardyos:restored" // on a restored copy: <source server>@<snapshot>
)

var (
	taskRE   = regexp.MustCompile(`^[a-z0-9]{6,16}$`)
	sourceRE = regexp.MustCompile(`^[a-z0-9]{6,32}$`)
	itemRE   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	childRE  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$`)
	snapRE   = regexp.MustCompile(`^hardyos-repl-([a-z0-9]{6,16})-([0-9]{8}T[0-9]{6}Z)$`)
	// A resume token: <version>-<checksum>-<length>-<compressed nvlist>, hex.
	tokenRE = regexp.MustCompile(`^[0-9]{1,3}-[0-9a-f]{1,32}-[0-9a-f]{1,16}-[0-9a-f]{2,}$`)
)

// ErrInvalid wraps a refused name or argument.
var ErrInvalid = errors.New("invalid")

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// ValidTask checks a replication task id (it's part of snapshot names).
func ValidTask(id string) error {
	if !taskRE.MatchString(id) {
		return invalid("task id %q: 6-16 lower-case letters and digits", id)
	}
	return nil
}

// ValidSource checks a source server's id on the receiving side.
func ValidSource(id string) error {
	if !sourceRE.MatchString(id) {
		return invalid("source id %q: 6-32 lower-case letters and digits", id)
	}
	return nil
}

// ValidKind checks an item kind.
func ValidKind(k string) error {
	switch k {
	case KindShare, KindApp, KindVM:
		return nil
	}
	return invalid("kind %q: share, app or vm", k)
}

// ValidItem checks an item id (a shared folder, app or VM id; each
// kind's own rules are stricter, this one keeps names safe for datasets).
func ValidItem(id string) error {
	if !itemRE.MatchString(id) || strings.HasSuffix(id, "-") {
		return invalid("item id %q", id)
	}
	return nil
}

// ValidChild checks a dataset below an item, relative to it ("" is the
// item itself; "disk0" a VM's first disk). At most 3 levels.
func ValidChild(child string) error {
	if child == "" {
		return nil
	}
	parts := strings.Split(child, "/")
	if len(parts) > 3 {
		return invalid("child %q: too deep", child)
	}
	for _, p := range parts {
		if !childRE.MatchString(p) || p == "." || p == ".." {
			return invalid("child %q", child)
		}
	}
	return nil
}

// ValidPool checks a pool name for replication (data pools only).
func ValidPool(pool string) error {
	if err := zfs.ValidPoolName(pool); err != nil {
		return invalid("%v", err)
	}
	return nil
}

// SnapName is a replication snapshot's label for a task at t.
func SnapName(task string, t time.Time) string {
	return SnapPrefix + task + "-" + t.UTC().Format(snapTimeFormat)
}

// ParseSnap reads a replication snapshot label: its task and time. ok is
// false for anything else (user, automatic, app, VM snapshots).
func ParseSnap(label string) (task string, at time.Time, ok bool) {
	m := snapRE.FindStringSubmatch(label)
	if m == nil {
		return "", time.Time{}, false
	}
	t, err := time.Parse(snapTimeFormat, m[2])
	if err != nil || t.Format(snapTimeFormat) != m[2] {
		return "", time.Time{}, false
	}
	return m[1], t, true
}

// ValidSnap checks a replication snapshot label, for task when it's not
// empty.
func ValidSnap(label, task string) error {
	tk, _, ok := ParseSnap(label)
	if !ok || (task != "" && tk != task) {
		return invalid("snapshot %q isn't a replication snapshot of this task", label)
	}
	return nil
}

// ValidToken checks the shape of a resume token (zfs send -t). What it
// names is checked against the expected snapshot before it's used.
func ValidToken(tok string) error {
	if len(tok) > 16384 || !tokenRE.MatchString(tok) {
		return invalid("resume token")
	}
	return nil
}

// Target is where a source's item lives on a receiving server.
type Target struct {
	Pool   string `json:"pool"`
	Source string `json:"source"`
	Kind   string `json:"kind"`
	Item   string `json:"item"`
	Child  string `json:"child"`
}

// Validate checks every component.
func (t Target) Validate() error {
	for _, err := range []error{ValidPool(t.Pool), ValidSource(t.Source), ValidKind(t.Kind), ValidItem(t.Item), ValidChild(t.Child)} {
		if err != nil {
			return err
		}
	}
	return zfs.ValidDatasetName(t.Dataset())
}

// RootDataset is <pool>/replicas.
func RootDataset(pool string) string { return pool + "/" + ReplicasDataset }

// SourceDataset is <pool>/replicas/<source>: the source's quota is set here.
func SourceDataset(pool, source string) string { return RootDataset(pool) + "/" + source }

// KindDataset is <pool>/replicas/<source>/<kind>.
func KindDataset(pool, source, kind string) string { return SourceDataset(pool, source) + "/" + kind }

// ItemDataset is the item's top dataset on the receiver.
func (t Target) ItemDataset() string { return KindDataset(t.Pool, t.Source, t.Kind) + "/" + t.Item }

// Dataset is the full dataset name on the receiver.
func (t Target) Dataset() string {
	if t.Child == "" {
		return t.ItemDataset()
	}
	return t.ItemDataset() + "/" + t.Child
}

// Mountpoint is where the dataset would mount: always under the pool's
// replicas folder, and never actually mounted (canmount=off).
func (t Target) Mountpoint() string {
	return zfs.MountRoot + "/" + t.Pool + "/" + ReplicasDataset + "/" + t.Source + "/" + t.Kind + "/" + t.Item + childSuffix(t.Child)
}

func childSuffix(child string) string {
	if child == "" {
		return ""
	}
	return "/" + child
}

// Under reports whether ds is the item dataset of t or below it.
func (t Target) Under(ds string) bool {
	item := t.ItemDataset()
	return ds == item || strings.HasPrefix(ds, item+"/")
}

// Item identifies something replicable on a source server.
type Item struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

// Validate checks the kind and id.
func (i Item) Validate() error {
	if err := ValidKind(i.Kind); err != nil {
		return err
	}
	return ValidItem(i.ID)
}

func (i Item) String() string { return i.Kind + "/" + i.ID }
