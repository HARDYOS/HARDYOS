package priv

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"

	"github.com/hardyos/hardyos/daemon/internal/cloudbackup"
)

// Cloud backup operation names (docs/backup.md). restic runs only through
// these, with arguments built from validated values; credentials never
// leave hardyd-priv except a destination's recovery kit.
const (
	OpCloudTargets      = "cloudbackup.targets"
	OpCloudTargetSave   = "cloudbackup.target.save"
	OpCloudTargetRemove = "cloudbackup.target.remove"
	OpCloudKit          = "cloudbackup.kit"
	OpCloudBackup       = "cloudbackup.backup"
	OpCloudRestore      = "cloudbackup.restore"
	OpCloudPrune        = "cloudbackup.prune"
	OpCloudCheck        = "cloudbackup.check"
	OpCloudRebuild      = "cloudbackup.rebuild"
	OpCloudTask         = "cloudbackup.task"
	OpCloudCancel       = "cloudbackup.cancel"
	OpCloudVersions     = "cloudbackup.versions"
	OpCloudBrowse       = "cloudbackup.browse"
	OpCloudOffer        = "cloudbackup.offer"
	OpCloudOfferDismiss = "cloudbackup.offer.dismiss"
	// Live installer only.
	OpInstallCloudProbe = "install.cloud.probe"
	OpInstallCloudStage = "install.cloud.stage"
)

// CloudTargetRef names a destination.
type CloudTargetRef struct {
	ID      string `json:"id"`
	Confirm string `json:"confirm,omitempty"`
}

// CloudCheckArgs checks a destination's repository.
type CloudCheckArgs struct {
	Target  string `json:"target"`
	Percent int    `json:"percent"`
}

// CloudTaskRef names a running task.
type CloudTaskRef struct {
	ID string `json:"id"`
}

// CloudTargetsResult lists the destinations.
type CloudTargetsResult struct {
	Targets []cloudbackup.Target `json:"targets"`
}

// CloudVersionsResult lists a destination's versions.
type CloudVersionsResult struct {
	Versions []cloudbackup.Version `json:"versions"`
}

// CloudBrowseResult lists a folder of a version.
type CloudBrowseResult struct {
	Entries []cloudbackup.Entry `json:"entries"`
}

// CloudOfferResult is a rebuilt server's pending rebuild (nil: none).
type CloudOfferResult struct {
	Offer *cloudbackup.RebuildOffer `json:"offer"`
}

// CloudProbeResult lists the versions an installer can restore.
type CloudProbeResult struct {
	Versions []cloudbackup.ProbeVersion `json:"versions"`
}

func cloudErr(err error) error {
	if err == nil {
		return nil
	}
	var p *cloudbackup.Problem
	if errors.As(err, &p) || errors.Is(err, cloudbackup.ErrNotFound) || errors.Is(err, cloudbackup.ErrRepoExists) || errors.Is(err, cloudbackup.ErrWrongKey) {
		return Errorf(CodeBadArgs, "%v", err)
	}
	return Errorf(CodeFailed, "%v", err)
}

// RegisterCloudBackup adds the cloud backup operations.
func RegisterCloudBackup(s *Server, r *cloudbackup.Root) {
	s.Handle(OpCloudTargets, func(ctx context.Context, _ json.RawMessage) (any, error) {
		l, err := r.Targets()
		return CloudTargetsResult{Targets: l}, cloudErr(err)
	})
	s.Handle(OpCloudTargetSave, typed(func(ctx context.Context, a cloudbackup.SaveArgs) (any, error) {
		res, err := r.Save(ctx, a)
		return res, cloudErr(err)
	}))
	s.Handle(OpCloudTargetRemove, typed(func(ctx context.Context, a CloudTargetRef) (any, error) {
		return map[string]bool{"removed": true}, cloudErr(r.Remove(a.ID, a.Confirm))
	}))
	s.Handle(OpCloudKit, typed(func(ctx context.Context, a CloudTargetRef) (any, error) {
		k, err := r.Kit(a.ID)
		return k, cloudErr(err)
	}))
	s.Handle(OpCloudBackup, typed(func(ctx context.Context, a cloudbackup.BackupArgs) (any, error) {
		t, err := r.StartBackup(a)
		return t, cloudErr(err)
	}))
	s.Handle(OpCloudRestore, typed(func(ctx context.Context, a cloudbackup.RestoreArgs) (any, error) {
		t, err := r.StartRestore(ctx, a)
		return t, cloudErr(err)
	}))
	s.Handle(OpCloudPrune, typed(func(ctx context.Context, a CloudTargetRef) (any, error) {
		t, err := r.StartPrune(a.ID)
		return t, cloudErr(err)
	}))
	s.Handle(OpCloudCheck, typed(func(ctx context.Context, a CloudCheckArgs) (any, error) {
		t, err := r.StartCheck(a.Target, a.Percent)
		return t, cloudErr(err)
	}))
	s.Handle(OpCloudRebuild, typed(func(ctx context.Context, a cloudbackup.RebuildArgs) (any, error) {
		t, err := r.StartRebuild(ctx, a)
		return t, cloudErr(err)
	}))
	s.Handle(OpCloudTask, typed(func(ctx context.Context, a CloudTaskRef) (any, error) {
		t, err := r.TaskStatus(a.ID)
		return t, cloudErr(err)
	}))
	s.Handle(OpCloudCancel, typed(func(ctx context.Context, a CloudTaskRef) (any, error) {
		return map[string]bool{"cancelled": r.CancelTask(a.ID)}, nil
	}))
	s.Handle(OpCloudVersions, typed(func(ctx context.Context, a CloudTargetRef) (any, error) {
		v, err := r.Versions(ctx, a.ID)
		return CloudVersionsResult{Versions: v}, cloudErr(err)
	}))
	s.Handle(OpCloudBrowse, typed(func(ctx context.Context, a cloudbackup.BrowseArgs) (any, error) {
		e, err := r.Browse(ctx, a)
		return CloudBrowseResult{Entries: e}, cloudErr(err)
	}))
	s.Handle(OpCloudOffer, func(ctx context.Context, _ json.RawMessage) (any, error) {
		return CloudOfferResult{Offer: r.Offer()}, nil
	})
	s.Handle(OpCloudOfferDismiss, func(ctx context.Context, _ json.RawMessage) (any, error) {
		return map[string]bool{"dismissed": true}, cloudErr(r.Dismiss())
	})
}

// RegisterInstallCloud adds the installer's "Restore from backup" steps:
// listing a repository's versions and staging one's settings into the new
// system at target. Live installer only.
func RegisterInstallCloud(s *Server, r *cloudbackup.Root, target string) {
	s.Handle(OpInstallCloudProbe, typed(func(ctx context.Context, a cloudbackup.ProbeArgs) (any, error) {
		v, err := r.Probe(ctx, a)
		return CloudProbeResult{Versions: v}, cloudErr(err)
	}))
	s.Handle(OpInstallCloudStage, typed(func(ctx context.Context, a cloudbackup.ProbeArgs) (any, error) {
		m, err := r.StageInto(ctx, a, target)
		return m, cloudErr(err)
	}))
}

// RootKeyFor derives a key for root's own sealing (cloud backup
// credentials) from the master key in keyDir (created on first use). Its
// label differs from secrets.key's, so no purpose hardyd can ask for
// yields the same key.
func RootKeyFor(keyDir, purpose string) ([]byte, error) {
	if !purposeRE.MatchString(purpose) {
		return nil, errors.New("bad purpose")
	}
	master, err := loadMasterKey(keyDir)
	if err != nil {
		return nil, err
	}
	m := hmac.New(sha256.New, master)
	_, _ = io.WriteString(m, "hardyos root v1\x00"+purpose)
	return m.Sum(nil), nil
}
