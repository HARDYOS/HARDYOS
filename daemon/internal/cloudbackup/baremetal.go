package cloudbackup

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"

	"github.com/hardyos/hardyos/daemon/internal/backup"
	"github.com/hardyos/hardyos/daemon/internal/rootfile"
)

// The installer's "Restore from backup": on the live system, before
// anything is stored, a destination is opened straight from what was
// typed in (the recovery kit and the bucket's keys).

// ProbeArgs opens a destination from the installer.
type ProbeArgs struct {
	Kit       string `json:"kit"` // the recovery kit's text
	AccessKey string `json:"accessKey"`
	SecretKey string `json:"secretKey"`
	Run       string `json:"run,omitempty"` // StageInto: the version
}

// ProbeVersion is a version the installer can restore from.
type ProbeVersion struct {
	Run      string    `json:"run"`
	Time     string    `json:"time"`
	Hostname string    `json:"hostname"`
	Items    []string  `json:"items"`
	Target   string    `json:"target"`
	Version  *Version  `json:"-"`
	Manifest *Manifest `json:"-"`
}

func (r *Root) probeRepo(a ProbeArgs) (*Repo, error) {
	k, err := ParseKit(a.Kit)
	if err != nil {
		return nil, err
	}
	t := k.Target
	if err := t.Normalize(r.AllowLocal); err != nil {
		return nil, err
	}
	creds := Credentials{AccessKey: strings.TrimSpace(a.AccessKey), SecretKey: strings.TrimSpace(a.SecretKey), RepoPassword: k.Key}
	if err := CheckCredentials(t.Kind, creds); err != nil {
		return nil, err
	}
	return &Repo{Target: t, Creds: creds}, nil
}

// Probe lists the versions in the repository that hold the settings,
// newest first.
func (r *Root) Probe(ctx context.Context, a ProbeArgs) ([]ProbeVersion, error) {
	repo, err := r.probeRepo(a)
	if err != nil {
		return nil, err
	}
	if err := CheckEndpoint(ctx, &repo.Target, r.resolver(), r.TestAllow); err != nil {
		return nil, err
	}
	ok, err := r.Restic.Exists(ctx, repo)
	if err != nil {
		return nil, accessError(err)
	}
	if !ok {
		return nil, problemf("there are no backups at that destination")
	}
	snaps, err := r.Restic.Snapshots(ctx, repo)
	if err != nil {
		return nil, err
	}
	out := []ProbeVersion{}
	for _, v := range GroupVersions(snaps) {
		has := false
		var items []string
		for _, it := range v.Items {
			has = has || it.Item == ItemSystem
			items = append(items, it.Item)
		}
		if !has || v.Manifest == "" {
			continue
		}
		pv := ProbeVersion{Run: v.Run, Time: v.Time.UTC().Format("2006-01-02T15:04:05Z"), Items: items, Target: repo.Target.ID}
		if len(out) < 5 {
			if m, err := r.readManifest(ctx, repo, v.Manifest); err == nil {
				pv.Hostname = m.Hostname
			}
		}
		out = append(out, pv)
		if len(out) >= 50 {
			break
		}
	}
	return out, nil
}

// StageInto stages a version's settings and domain into the new system at
// targetRoot (applied by hardyd-priv at its first start) and leaves the
// destination there for the first start (ConnectFile).
func (r *Root) StageInto(ctx context.Context, a ProbeArgs, targetRoot string) (*backup.Manifest, error) {
	if err := ValidRunID(a.Run); err != nil {
		return nil, err
	}
	repo, err := r.probeRepo(a)
	if err != nil {
		return nil, err
	}
	if !filepath.IsAbs(targetRoot) || targetRoot == "/" {
		return nil, errors.New("no new system to restore into")
	}
	snaps, err := r.Restic.Snapshots(ctx, repo)
	if err != nil {
		return nil, accessError(err)
	}
	var sys *Snapshot
	for i := range snaps {
		if snaps[i].Tag("run") == a.Run && snaps[i].Tag("item") == ItemSystem {
			sys = &snaps[i]
		}
	}
	if sys == nil {
		return nil, problemf("that version has no settings")
	}
	c, err := r.readSettings(ctx, repo, sys)
	if err != nil {
		return nil, err
	}
	if c.Manifest.Users == 0 {
		return nil, problemf("the backup's settings have no accounts")
	}
	br := &backup.Root{Root: targetRoot, UID: -1, GID: -1}
	if _, err := br.StageContents(c); err != nil {
		return nil, err
	}
	if id := sys.Tag("server"); serverIDRE.MatchString(id) {
		if err := rootfile.WriteInRootDir(filepath.Join(targetRoot, strings.TrimPrefix(DefaultDir, "/"), ServerIDFile), []byte(id+"\n"), 0o600, 0o700); err != nil {
			return nil, err
		}
	}
	b, _ := json.Marshal(Connect{Target: repo.Target, Creds: repo.Creds, Run: a.Run})
	if err := rootfile.WriteInRootDir(filepath.Join(targetRoot, strings.TrimPrefix(DefaultDir, "/"), ConnectFile), b, 0o600, 0o700); err != nil {
		return nil, err
	}
	return &c.Manifest, nil
}
