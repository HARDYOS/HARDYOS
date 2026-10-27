package cloudbackup

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/apps"
	"github.com/hardyos/hardyos/daemon/internal/backup"
	"github.com/hardyos/hardyos/daemon/internal/fileworker"
	"github.com/hardyos/hardyos/daemon/internal/rootfile"
	"github.com/hardyos/hardyos/daemon/internal/shares"
	"github.com/hardyos/hardyos/daemon/internal/vms"
)

// Shares is what backups need of the shared folders (shares.Manager).
type Shares interface {
	List(ctx context.Context) ([]shares.Share, error)
	Create(ctx context.Context, a shares.NewShare) (*shares.Share, error)
}

// Apps is what backups need of the apps engine (apps.Manager).
type Apps interface {
	BackupSource(ctx context.Context, id string) (*apps.BackupSource, error)
	BackupSources(ctx context.Context) ([]apps.BackupSource, error)
	RestoreData(ctx context.Context, id, confirm string, fill apps.Fill) error
	RestoreNew(ctx context.Context, id, pool string, fill apps.Fill) error
}

// VMs is what backups need of the VM manager (vms.Manager).
type VMs interface {
	BackupIDs(ctx context.Context) ([]string, error)
	BackupSnapshot(ctx context.Context, id, snap string) (*vms.BackupSnap, error)
	ReleaseBackupSnapshot(ctx context.Context, id, snap string) error
	RestoreFromBackup(ctx context.Context, id, confirm string, f vms.RestoreFill) (*vms.VM, error)
	RestoreNewFromBackup(ctx context.Context, pool string, f vms.RestoreFill) (*vms.VM, error)
	Get(ctx context.Context, id string) (*vms.VM, error)
}

// System collects the server's settings files (backup.Root) and stages a
// settings restore for the next start.
type System interface {
	Collect(ctx context.Context, secrets bool) ([]backup.File, error)
	StageContents(c *backup.Contents) (*backup.Staged, error)
}

// Files runs file operations as a person (fileworker.Server), for
// restores people make of their own files.
type Files interface {
	Do(ctx context.Context, op string, a fileworker.Args) (json.RawMessage, *os.File, error)
	DoIn(ctx context.Context, op string, who fileworker.Who, in fileworker.Root, a fileworker.Args) (json.RawMessage, *os.File, error)
	RulesLevel(ctx context.Context, who fileworker.Who, share string) (string, error)
}

// Root runs cloud backups inside hardyd-priv.
type Root struct {
	Restic *Restic
	Vol    Volumes
	Shares Shares
	Apps   Apps   // nil: apps can't be backed up
	VMs    VMs    // nil: VMs can't be backed up
	System System // nil: no settings in backups
	Files  Files  // nil: people can't restore their own files
	// Dir is root's state directory for backups
	// (rootfile.RootStateDir/cloudbackup).
	Dir string
	// WorkDir is hardyd's work directory, where it leaves the database
	// copy for a backup (backup.WorkDir under /).
	WorkDir string
	// Key returns the 32-byte sealing key (derived from the master key).
	Key func() ([]byte, error)
	// DBOwner is hardyd's user ID: the database copy for a settings backup
	// must be its own (0: not checked, tests).
	DBOwner int
	// AllowLocal permits local: repositories (tests only).
	AllowLocal bool
	// Resolver checks endpoints when a destination is saved; nil = DNS.
	Resolver Resolver
	// TestAllow widens the address check (tests with a fake S3 on
	// loopback).
	TestAllow func(netip.Addr) bool
	Log       *slog.Logger
	Now       func() time.Time
	// AccessTimeout bounds the access test when a destination is saved
	// (default 90 s).
	AccessTimeout time.Duration

	store     targetStore
	storeOnce sync.Once
	tasks     taskTable
	itemMu    sync.Mutex
	items     map[string]*sync.Mutex
	idMu      sync.Mutex
	serverID  string
	lim       limits
}

// DefaultDir is root's backup state directory.
var DefaultDir = filepath.Join(rootfile.RootStateDir, "cloudbackup")

func (r *Root) log() *slog.Logger {
	if r.Log != nil {
		return r.Log
	}
	return slog.Default()
}

func (r *Root) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}

func (r *Root) targets() *targetStore {
	r.storeOnce.Do(func() {
		dir := r.Dir
		if dir == "" {
			dir = DefaultDir
		}
		r.store = targetStore{dir: dir, key: r.Key}
	})
	return &r.store
}

func (r *Root) resolver() Resolver {
	if r.Resolver != nil {
		return r.Resolver
	}
	return defaultResolver{}
}

// itemLock serializes work on one item (its stable mount folder).
func (r *Root) itemLock(key string) func() {
	r.itemMu.Lock()
	if r.items == nil {
		r.items = map[string]*sync.Mutex{}
	}
	l := r.items[key]
	if l == nil {
		l = &sync.Mutex{}
		r.items[key] = l
	}
	r.itemMu.Unlock()
	l.Lock()
	return l.Unlock
}

func randomID(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ---- destinations ---------------------------------------------------------------

// Targets lists the destinations (nothing secret).
func (r *Root) Targets() ([]Target, error) { return r.targets().list() }

// SaveArgs creates or changes a destination.
type SaveArgs struct {
	Target Target `json:"target"`
	// Credentials: on a change, empty keys keep the saved ones.
	AccessKey string `json:"accessKey,omitempty"`
	SecretKey string `json:"secretKey,omitempty"`
	// RepoPassword connects to an existing repository (from its recovery
	// kit). Empty: HardyOS makes a new repository with a new key, or
	// refuses when there already is one.
	RepoPassword string `json:"repoPassword,omitempty"`
	// Update: the destination exists and is being changed (its key stays).
	Update bool `json:"update,omitempty"`
}

// SaveResult says what saving did.
type SaveResult struct {
	Target Target `json:"target"`
	// Created: HardyOS made a new repository (download the recovery kit).
	Created bool `json:"created"`
}

// Errors from Save.
var (
	ErrRepoExists = errors.New("there's already a backup repository there; to use it, enter the key from its recovery kit")
)

// Save tests access to a destination and keeps it: a new repository is
// created with a generated key when there's none; an existing one is used
// only with its key.
func (r *Root) Save(ctx context.Context, a SaveArgs) (*SaveResult, error) {
	t := a.Target
	if err := t.Normalize(r.AllowLocal); err != nil {
		return nil, err
	}
	st := r.targets()
	var creds Credentials
	if a.Update {
		old, err := st.get(t.ID)
		if err != nil {
			return nil, err
		}
		if old.Target.Kind != t.Kind {
			return nil, problemf("a destination's kind can't change; add a new one")
		}
		creds = old.Creds
		t.CreatedAt = old.Target.CreatedAt
		// The saved keys never go to another host (decision 183).
		if endpointHost(&old.Target) != endpointHost(&t) && (a.AccessKey == "" || a.SecretKey == "") {
			return nil, problemf("the destination's address changed: enter its access keys again")
		}
		if old.Target.Repository() != t.Repository() && a.RepoPassword == "" {
			return nil, problemf("this is another repository now: enter the key from its recovery kit, or add it as a new destination")
		}
	} else {
		if _, err := st.get(t.ID); err == nil {
			return nil, problemf("there's already a destination with the id %s", t.ID)
		}
		t.CreatedAt = r.now()
	}
	if a.AccessKey != "" || a.SecretKey != "" || !a.Update {
		creds.AccessKey, creds.SecretKey = a.AccessKey, a.SecretKey
	}
	if err := CheckCredentials(t.Kind, creds); err != nil {
		return nil, err
	}
	if a.RepoPassword != "" {
		if err := ValidRepoPassword(a.RepoPassword); err != nil {
			return nil, err
		}
		creds.RepoPassword = a.RepoPassword
	}
	if err := CheckEndpoint(ctx, &t, r.resolver(), r.TestAllow); err != nil {
		return nil, err
	}
	created := false
	ctx, cancel := context.WithTimeout(ctx, r.accessTimeout())
	defer cancel()
	if creds.RepoPassword == "" {
		pw, err := NewRepoPassword()
		if err != nil {
			return nil, err
		}
		creds.RepoPassword = pw
		repo := &Repo{Target: t, Creds: creds}
		ok, err := r.Restic.Exists(ctx, repo)
		switch {
		case errors.Is(err, ErrWrongKey):
			return nil, ErrRepoExists
		case err != nil:
			return nil, accessError(err)
		case ok:
			return nil, ErrRepoExists
		}
		if err := r.Restic.Init(ctx, repo); err != nil {
			return nil, accessError(err)
		}
		created = true
	} else {
		repo := &Repo{Target: t, Creds: creds}
		ok, err := r.Restic.Exists(ctx, repo)
		switch {
		case err != nil:
			return nil, accessError(err)
		case !ok:
			return nil, problemf("there's no backup repository there; leave the key empty to create one")
		}
	}
	t.AccessKeyHint = hint(creds.AccessKey)
	if err := st.put(&Repo{Target: t, Creds: creds}); err != nil {
		return nil, err
	}
	r.log().Info("cloud backup: destination saved", "target", t.ID, "kind", t.Kind, "created", created)
	return &SaveResult{Target: t, Created: created}, nil
}

// endpointHost is where a destination's keys are sent.
func endpointHost(t *Target) string {
	if t.Kind != KindS3 {
		return string(t.Kind)
	}
	h, p, err := ParseEndpoint(t.Endpoint)
	if err != nil {
		return t.Endpoint
	}
	return strings.ToLower(h) + ":" + strconv.Itoa(p)
}

// accessTimeout bounds testing a destination (restic retries some
// errors, such as an unknown access key, for many minutes).
func (r *Root) accessTimeout() time.Duration {
	if r.AccessTimeout > 0 {
		return r.AccessTimeout
	}
	return 90 * time.Second
}

// accessError explains a failed access test.
func accessError(err error) error {
	if errors.Is(err, ErrWrongKey) || errors.Is(err, ErrLocked) {
		return err
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return &Problem{Msg: "the bucket didn't answer in time: check the endpoint, the bucket's name and the keys"}
	}
	var p *Problem
	if errors.As(err, &p) {
		return err
	}
	return &Problem{Msg: "couldn't reach the bucket with these settings: " + err.Error()}
}

// Remove forgets a destination on this server. The repository and the
// backups in it are left as they are. Confirm is its name.
func (r *Root) Remove(id, confirm string) error {
	repo, err := r.targets().get(id)
	if err != nil {
		return err
	}
	if strings.TrimSpace(confirm) != repo.Target.Name && confirm != id {
		return problemf("type the destination's name (%s) to confirm", repo.Target.Name)
	}
	return r.targets().remove(id)
}

// RecoveryKit is everything needed to reach the backups from a new server.
type RecoveryKit struct {
	Target     Target `json:"target"`
	Repository string `json:"repository"`
	Key        string `json:"key"`
}

// Kit returns a destination's recovery kit. hardyd asks only after the
// administrator entered their password again (and audits it).
func (r *Root) Kit(id string) (*RecoveryKit, error) {
	repo, err := r.targets().get(id)
	if err != nil {
		return nil, err
	}
	r.log().Info("cloud backup: recovery kit handed out", "target", id)
	return &RecoveryKit{Target: repo.Target, Repository: repo.Target.Repository(), Key: repo.Creds.RepoPassword}, nil
}

// repo opens a destination.
func (r *Root) repo(id string) (*Repo, error) {
	if err := ValidID(id); err != nil {
		return nil, err
	}
	return r.targets().get(id)
}

// ---- items --------------------------------------------------------------------

// Item kinds.
const (
	ItemShare  = "share"
	ItemApp    = "app"
	ItemVM     = "vm"
	ItemSystem = "system"
)

// Item is one thing a task backs up.
type Item struct {
	Kind string `json:"kind"`
	ID   string `json:"id,omitempty"` // empty for system
}

var itemIDRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// Check validates an item.
func (it Item) Check() error {
	switch it.Kind {
	case ItemSystem:
		if it.ID != "" {
			return problemf("the system item has no id")
		}
		return nil
	case ItemShare, ItemApp, ItemVM:
		if !itemIDRE.MatchString(it.ID) {
			return problemf("%q isn't a valid %s id", it.ID, it.Kind)
		}
		return nil
	}
	return problemf("unknown item kind %q", it.Kind)
}

// Key is the item's tag value: share:media, system.
func (it Item) Key() string {
	if it.Kind == ItemSystem {
		return ItemSystem
	}
	return it.Kind + ":" + it.ID
}

// ParseItem reads an item key.
func ParseItem(key string) (Item, error) {
	if key == ItemSystem {
		return Item{Kind: ItemSystem}, nil
	}
	k, id, ok := strings.Cut(key, ":")
	it := Item{Kind: k, ID: id}
	if !ok || k == ItemSystem {
		return it, problemf("bad item %q", key)
	}
	return it, it.Check()
}

var runIDRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)

// ValidRunID checks a run id from hardyd.
func ValidRunID(id string) error {
	if !runIDRE.MatchString(id) {
		return problemf("bad run id")
	}
	return nil
}
