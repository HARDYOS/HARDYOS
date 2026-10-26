package smb

// SFTP and WebDAV settings and the SFTP views (file sharing part E). The
// file server owns what they need: the domain membership, the accounts
// (winbind), the home folders and File Services' settings. The views
// themselves are internal/sftp's.

import (
	"context"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/hardyos/hardyos/daemon/internal/fileworker"
	"github.com/hardyos/hardyos/daemon/internal/sftp"
	"github.com/hardyos/hardyos/daemon/internal/shares"
)

// maxSFTPUsers bounds how many accounts get a view.
const maxSFTPUsers = 5000

// accounts lists the domain's turned-on accounts, cached between the
// 10-minute refreshes (shared folder changes reuse the list).
func (m *Manager) accounts(ctx context.Context, force bool) ([]string, error) {
	if !force && m.users != nil && m.now().Sub(m.usersAt) < HomesInterval {
		return m.users, nil
	}
	l, err := m.enabledUsers(ctx)
	if err != nil {
		if m.users != nil {
			return m.users, err
		}
		return nil, err
	}
	m.users, m.usersAt = l, m.now()
	return l, nil
}

func (m *Manager) lookupUser(ctx context.Context, name string) (*fileworker.Identity, error) {
	if m.LookupUser != nil {
		return m.LookupUser(ctx, name)
	}
	return fileworker.HelperLookup(ctx, name)
}

// nssName is the name NSS gives a user ID (HOME\alice as winbind spells it).
func (m *Manager) nssName(ctx context.Context, uid int) string {
	res, err := m.Runner.Run(ctx, nil, "getent", "passwd", strconv.Itoa(uid))
	if err != nil || res.ExitCode != 0 {
		return ""
	}
	n, _, _ := strings.Cut(strings.TrimSpace(string(res.Stdout)), ":")
	return n
}

// applySFTP brings the SFTP views in step; m.mu is held. joined false (or
// SFTP off) takes them away.
func (m *Manager) applySFTP(ctx context.Context, joined bool, set Settings, dom *Domain, list []shares.Share, homes string, force bool) {
	if m.SFTP == nil {
		return
	}
	on := joined && set.SFTPEnabled
	if !on {
		if _, err := m.SFTP.Apply(ctx, false, nil, nil); err != nil {
			m.log().Warn("sftp: turning off", "err", err)
		}
		return
	}
	names := m.names(ctx)
	nb := strings.ToUpper(dom.NetBIOS)
	var adminGIDs []int
	if gid, err := names.GroupID(nb + `\` + domainAdminsGroup); err == nil {
		adminGIDs = append(adminGIDs, int(gid))
	} else {
		// winbind can't answer: keep the views as they are.
		m.log().Warn("sftp: the domain's groups can't be looked up; views unchanged", "err", err)
		return
	}
	if dom.AdminsGroupSID != "" {
		if gid, err := names.GroupIDBySID(dom.AdminsGroupSID); err == nil {
			adminGIDs = append(adminGIDs, int(gid))
		}
	}
	gids := map[string]int{}
	groupID := func(name string) (int, bool) {
		rn := ruleName(nb, name)
		if rn == "" {
			return 0, false
		}
		k := strings.ToLower(rn)
		if g, ok := gids[k]; ok {
			return g, g > 0
		}
		g, err := names.GroupID(rn)
		if err != nil {
			gids[k] = 0
			return 0, false
		}
		gids[k] = int(g)
		return int(g), true
	}
	var folders []sftp.Folder
	for _, sh := range list {
		if !sh.Services.SFTP || !sh.Mounted || !filepath.IsAbs(sh.Path) || m.released[sh.ID] {
			continue
		}
		folders = append(folders, sftp.Folder{ID: sh.ID, Name: sh.Name, Path: sh.Path, Dataset: sh.Dataset, Rules: sh.Access})
	}
	accts, err := m.accounts(ctx, force)
	if err != nil {
		m.log().Warn("sftp: listing the domain's accounts", "err", err)
		if accts == nil {
			return
		}
	}
	if len(accts) > maxSFTPUsers {
		m.log().Warn("sftp: too many accounts; only the first get a view", "accounts", len(accts), "max", maxSFTPUsers)
		accts = accts[:maxSFTPUsers]
	}
	var users []sftp.User
	for _, a := range accts {
		principal := nb + `\` + a
		id, err := m.lookupUser(ctx, principal)
		if err != nil || id.UID < sftp.DomainUIDLow || id.UID > sftp.DomainUIDHigh || id.GID == 0 {
			continue
		}
		u := sftp.User{Principal: principal, Name: m.nssName(ctx, id.UID), UID: id.UID, GID: id.GID, Groups: id.Groups}
		for _, g := range append([]int{id.GID}, id.Groups...) {
			for _, ag := range adminGIDs {
				if g == ag {
					u.Admin = true
				}
			}
		}
		if homes != "" && set.Homes.Pool != "" {
			hn := HomeName(dom.NetBIOS, a)
			u.Home = filepath.Join(homes, hn)
			u.HomeDataset = HomesDataset(set.Homes.Pool) + "/" + hn
		}
		users = append(users, u)
	}
	binds := sftp.Plan(users, folders, groupID)
	if _, err := m.SFTP.Apply(ctx, true, users, binds); err != nil {
		m.log().Warn("sftp: applying", "err", err)
	}
}

// releaseSFTP lets go of a shared folder's dataset before it's destroyed.
func (m *Manager) releaseSFTP(ds string) {
	if m.SFTP == nil || ds == "" {
		return
	}
	if err := m.SFTP.Release(ds); err != nil {
		m.log().Warn("sftp: unmounting a shared folder that's going away", "dataset", ds, "err", err)
	}
}

// ReleaseDataset lets go of every SFTP bind of a dataset or pool (before
// it's destroyed or exported).
func (m *Manager) ReleaseDataset(_ context.Context, ds string) error {
	if m.SFTP == nil {
		return nil
	}
	return m.SFTP.Release(ds)
}

// sftpStatus is SFTP's part of Status.
func (m *Manager) sftpStatus(ctx context.Context, set Settings) *sftp.Status {
	if m.SFTP == nil {
		return nil
	}
	st := m.SFTP.Status(ctx)
	st.Enabled = set.SFTPEnabled
	return &st
}
