package shares

import (
	"context"
	"fmt"
)

// Helpers for restoring a shared folder from a replica (internal/replica).

// RestoreProps checks a new shared folder that a restore brings back and
// returns the properties (name=value) it's received with. It starts
// closed: only administrators have access, no apps, no recycle bin or
// guest access, and SMB off, so nothing is published before an
// administrator has looked at it. The pool's shares dataset is made if
// it's missing.
func (m *Manager) RestoreProps(ctx context.Context, pool, id, name string) ([]string, error) {
	sv := DefaultServices()
	sv.SMB.Enabled = false
	a, err := CheckNew(NewShare{Pool: pool, ID: id, Name: name, Access: []Rule{}, Services: &sv})
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	l, err := m.List(ctx)
	if err != nil {
		return nil, err
	}
	for _, sh := range l {
		if sh.ID == a.ID {
			return nil, invalid("there's already a shared folder with the id %q (%s, on %s)", a.ID, sh.Name, sh.Pool)
		}
	}
	if sh := nameTaken(l, a.Name, ""); sh != nil {
		return nil, invalid("there's already a shared folder called %s (on %s)", sh.Name, sh.Pool)
	}
	if _, err := m.zfs(ctx, "list", "-H", "-o", "name", a.Pool); err != nil {
		return nil, invalid("there's no pool called %s", a.Pool)
	}
	parent := SharesDataset(a.Pool)
	if _, err := m.zfs(ctx, "list", "-H", "-o", "name", parent); err != nil {
		if _, err := m.zfs(ctx, "create", "-o", "org.hardyos:role=shares", parent); err != nil {
			return nil, fmt.Errorf("creating %s: %w", parent, err)
		}
	}
	access := mustJSON(a.Access)
	if len(a.Access) == 0 {
		access = "[]"
	}
	return []string{
		"acltype=posixacl", "xattr=sa", "aclinherit=passthrough", "devices=off", "setuid=off",
		PropShare + "=1", PropName + "=" + a.Name,
		PropAccess + "=" + access, PropApps + "=[]",
		PropRecycle + "=off", PropGuest + "=off", PropServices + "=" + mustJSON(*a.Services),
	}, nil
}

// AdoptRestored reads a restored shared folder back once it's mounted.
func (m *Manager) AdoptRestored(ctx context.Context, pool, id string) (*Share, error) {
	if err := ValidID(id); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	sh, err := m.reread(ctx, Dataset(pool, id))
	if err != nil {
		return nil, err
	}
	m.log().Info("shared folder restored from a replica", "id", sh.ID, "dataset", sh.Dataset)
	return sh, nil
}
