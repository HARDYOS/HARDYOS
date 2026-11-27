package shares

// A shared folder moving to the storage server with an app made highly
// available (docs/plans/cluster-gaps-2.md, decisions 500-503): its
// settings travel as values checked like a person's input and are written
// as the dataset's properties there (a plain zfs send carries none), and
// from the conversion's final snapshot until it is parked it is held:
// read-only and unmounted, so no file service, app or backup uses it and
// nobody writes a copy the storage server no longer gets.

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// PropHAHold marks a shared folder held by a conversion (its id), as
// apps.PropHAHold marks an app.
const PropHAHold = "org.hardyos:ha-hold"

// PropHAReleased marks a shared folder the storage server adopted that
// its conversion let go of (its id): shared from there since, so it may
// have been written (decision 507). An adopt asked again leaves such a
// folder as it is; one without it is held again.
const PropHAReleased = "org.hardyos:ha-released"

var holdConvRE = regexp.MustCompile(`^[a-z0-9]{8,32}$`)

// Settings are a shared folder's own settings: what moves with it.
type Settings struct {
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	QuotaBytes  uint64     `json:"quotaBytes,omitempty"`
	Recycle     bool       `json:"recycle"`
	Guest       bool       `json:"guest"`
	Access      []Rule     `json:"access"`
	Apps        []AppGrant `json:"apps"`
	Services    Services   `json:"services"`
}

// SettingsOf is a shared folder's settings.
func SettingsOf(sh *Share) Settings {
	return Settings{Name: sh.Name, Description: sh.Description, QuotaBytes: sh.QuotaBytes, Recycle: sh.Recycle, Guest: sh.Guest,
		Access: append([]Rule{}, sh.Access...), Apps: append([]AppGrant{}, sh.Apps...), Services: sh.Services}
}

// Check validates settings as a person's input is validated.
func (s Settings) Check() (Settings, error) {
	n, err := CleanName(s.Name)
	if err != nil {
		return s, err
	}
	if n != s.Name {
		return s, invalid("the shared folder's name isn't tidy")
	}
	if s.Description, err = cleanDescription(s.Description); err != nil {
		return s, err
	}
	if s.Access, err = CleanRules(s.Access); err != nil {
		return s, err
	}
	if err := checkPropSize(s.Access); err != nil {
		return s, err
	}
	if len(s.Apps) > MaxRules {
		return s, invalid("too many apps")
	}
	for _, g := range s.Apps {
		if err := ValidAppGrant(g.App, g.UID); err != nil {
			return s, err
		}
		if g.Level != LevelRead && g.Level != LevelWrite {
			return s, invalid("app access %q isn't read or write", g.Level)
		}
	}
	if s.Apps == nil {
		s.Apps = []AppGrant{}
	}
	if s.Services, err = CheckServices(s.Services); err != nil {
		return s, err
	}
	if s.QuotaBytes != 0 && s.QuotaBytes < minQuota {
		return s, invalid("the quota is too small")
	}
	return s, nil
}

// Props are the dataset properties holding checked settings, as
// "name=value" for zfs set.
func (s Settings) Props() []string {
	out := []string{PropShare + "=1", PropName + "=" + s.Name, PropAccess + "=" + mustJSON(s.Access), PropApps + "=" + mustJSON(s.Apps),
		PropRecycle + "=" + onOff(s.Recycle), PropGuest + "=" + onOff(s.Guest), PropServices + "=" + mustJSON(s.Services)}
	if s.Description != "" {
		out = append(out, PropDescription+"="+s.Description)
	}
	if s.QuotaBytes > 0 {
		out = append(out, "quota="+strconv.FormatUint(s.QuotaBytes, 10))
	}
	return out
}

// Taken refuses a shared folder id or name this server has already.
func (m *Manager) Taken(ctx context.Context, id, name string) error {
	l, err := m.List(ctx)
	if err != nil {
		return err
	}
	for _, sh := range l {
		if sh.ID == id {
			return invalid("this server has a shared folder with the id %q already (%s, on %s)", id, sh.Name, sh.Pool)
		}
	}
	if sh := nameTaken(l, name, ""); sh != nil {
		return invalid("this server has a shared folder called %s already (on %s)", sh.Name, sh.Pool)
	}
	return nil
}

// HAHoldArgs is shares.ha.hold.
type HAHoldArgs struct {
	ID   string `json:"id"`
	Conv string `json:"conv"`
	// Release ends the hold (its own conversion's only).
	Release bool `json:"release,omitempty"`
	// Adopted: the storage server lets go of a folder it adopted for the
	// conversion: refused when that conversion doesn't hold it (unless it
	// let go of it already), and marked released (PropHAReleased).
	Adopted bool `json:"adopted,omitempty"`
}

// HAHold holds a shared folder for a conversion: marked, read-only and
// unmounted (canmount=noauto, so a boot doesn't mount it either), so it
// lists as not mounted and no file service, app or backup uses it, and
// changes to it are refused until the hold ends. The caller lets the file
// services go of it first (priv's share hooks); a folder still in use
// can't be unmounted, and the hold is then taken back.
func (m *Manager) HAHold(ctx context.Context, a HAHoldArgs) error {
	if !holdConvRE.MatchString(a.Conv) {
		return invalid("bad conversion id")
	}
	if err := ValidID(a.ID); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var ds string
	for _, sh := range m.listOrNil(ctx) {
		if sh.ID == a.ID {
			ds = sh.Dataset
		}
	}
	if ds == "" || !shareDatasetRE.MatchString(ds) {
		return ErrNotFound
	}
	cur := m.heldBy(ctx, ds)
	if a.Release {
		if cur == "" {
			if a.Adopted && m.localValue(ctx, ds, PropHAReleased) != a.Conv {
				return invalid("that shared folder isn't held by this conversion")
			}
			return nil
		}
		if cur != a.Conv {
			return invalid("another conversion holds that shared folder")
		}
		if a.Adopted {
			// Marked first: from here on it may be written, and stays so.
			if _, err := m.zfs(ctx, "set", PropHAReleased+"="+a.Conv, ds); err != nil {
				return err
			}
		}
		for _, p := range []string{"readonly", PropHAHold} {
			if _, err := m.zfs(ctx, "inherit", p, ds); err != nil {
				return err
			}
		}
		if _, err := m.zfs(ctx, "set", "canmount=on", ds); err != nil {
			return err
		}
		if out, _ := m.zfs(ctx, "get", "-H", "-o", "value", "mounted", ds); strings.TrimSpace(string(out)) != "yes" {
			if _, err := m.zfs(ctx, "mount", ds); err != nil {
				return fmt.Errorf("mounting %s again: %w", ds, err)
			}
		}
		m.log().Info("shares: a conversion let go of a shared folder", "share", a.ID, "conv", a.Conv)
		return nil
	}
	if cur != "" && cur != a.Conv {
		return invalid("another conversion holds that shared folder")
	}
	if _, err := m.zfs(ctx, "set", "canmount=noauto", "readonly=on", PropHAHold+"="+a.Conv, ds); err != nil {
		return err
	}
	if out, _ := m.zfs(ctx, "get", "-H", "-o", "value", "mounted", ds); strings.TrimSpace(string(out)) == "yes" {
		if _, err := m.zfs(ctx, "unmount", ds); err != nil {
			// Still in use (a file left open): no hold, as it was.
			back := context.WithoutCancel(ctx)
			_, _ = m.zfs(back, "inherit", "readonly", ds)
			_, _ = m.zfs(back, "inherit", PropHAHold, ds)
			_, _ = m.zfs(back, "set", "canmount=on", ds)
			return fmt.Errorf("the shared folder is still in use on this server (a file is open in it); close it and try again: %w", err)
		}
	}
	m.log().Warn("shares: held for a conversion (read-only, unmounted, not shared)", "share", a.ID, "conv", a.Conv)
	return nil
}

func (m *Manager) listOrNil(ctx context.Context) []Share {
	l, err := m.List(ctx)
	if err != nil {
		return nil
	}
	return l
}

// heldBy is the conversion holding a shared folder's dataset ("" none:
// only a conversion id is a hold).
func (m *Manager) heldBy(ctx context.Context, ds string) string {
	return m.localValue(ctx, ds, PropHAHold)
}

// localValue is a conversion id set on the dataset itself ("" none).
func (m *Manager) localValue(ctx context.Context, ds, prop string) string {
	out, err := m.zfs(ctx, "get", "-H", "-p", "-s", "local", "-o", "value", prop, ds)
	if err != nil {
		return ""
	}
	v := strings.TrimSpace(string(out))
	if holdConvRE.MatchString(v) {
		return v
	}
	return ""
}

// HeldBy is the conversion holding shared folder id ("" none).
func (m *Manager) HeldBy(ctx context.Context, id string) string {
	if ValidID(id) != nil {
		return ""
	}
	for _, sh := range m.listOrNil(ctx) {
		if sh.ID == id {
			return m.heldBy(ctx, sh.Dataset)
		}
	}
	return ""
}

// refuseHeld refuses changing a held shared folder.
func (m *Manager) refuseHeld(ctx context.Context, sh *Share) error {
	if conv := m.heldBy(ctx, sh.Dataset); conv != "" {
		return invalid("%s is being moved to cluster storage (conversion %s); resume, abandon or undo that first", sh.Name, conv)
	}
	return nil
}
