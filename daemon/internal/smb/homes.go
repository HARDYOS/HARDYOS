package smb

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/shares"
	"github.com/hardyos/hardyos/daemon/internal/zfs"
	"golang.org/x/sys/unix"
)

// Home folders: <pool>/homes holds one dataset per domain account,
// <pool>/homes/<netbios>.<user> (lower case), owned by the account with mode
// 0700. Samba's [homes] finds them through winbind's template homedir, so
// nothing runs as root when someone connects.

// HomesDataset is the parent of the home folders on a pool.
func HomesDataset(pool string) string { return pool + "/homes" }

var (
	samRE      = regexp.MustCompile(`(?m)^sAMAccountName:\s*(\S.*?)\s*$`)
	homeUserRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
)

// noHome are accounts that never get a home folder.
var noHome = map[string]bool{"krbtgt": true, "guest": true}

// HomeName is a domain account's home dataset's last part: home.alice.
func HomeName(netbios, user string) string {
	return strings.ToLower(netbios) + "." + strings.ToLower(user)
}

// homesRoot makes <pool>/homes if needed and returns where it's mounted.
func (m *Manager) homesRoot(ctx context.Context, pool string) (string, error) {
	if err := zfs.ValidPoolName(pool); err != nil {
		return "", err
	}
	ds := HomesDataset(pool)
	if res, err := m.Runner.Run(ctx, nil, "zfs", "list", "-H", "-o", "name", ds); err != nil || res.ExitCode != 0 {
		if _, err := m.sysOutput(ctx, "zfs", "create", "-o", "acltype=posixacl", "-o", "xattr=sa", "-o", "aclinherit=passthrough",
			"-o", "devices=off", "-o", "setuid=off", "-o", "org.hardyos:role=homes", ds); err != nil {
			return "", fmt.Errorf("creating %s: %w", ds, err)
		}
	}
	out, err := m.sysOutput(ctx, "zfs", "get", "-H", "-o", "value", "mounted,mountpoint", ds)
	if err != nil {
		return "", err
	}
	f := strings.Fields(string(out))
	if len(f) != 2 || f[0] != "yes" || !filepath.IsAbs(f[1]) || filepath.Clean(f[1]) != f[1] || strings.ContainsAny(f[1], "%\\\" ") {
		return "", fmt.Errorf("%s isn't mounted", ds)
	}
	// The pool says where it's mounted; the kernel must agree before root
	// changes anything there.
	dev, err := m.verifyMount(f[1], ds)
	if err != nil {
		return "", fmt.Errorf("%s: %w", ds, err)
	}
	fd, err := shares.OpenRoot(f[1], dev, unix.O_RDONLY)
	if err != nil {
		return "", err
	}
	defer unix.Close(fd)
	// People may pass through to their own folder, not list the others.
	if err := unix.Fchmod(fd, 0o711); err != nil {
		return "", err
	}
	return f[1], nil
}

// enabledUsers lists the domain's turned-on accounts, asked with this
// server's machine account.
func (m *Manager) enabledUsers(ctx context.Context) ([]string, error) {
	sctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	out, err := m.net(sctx, "ads", "search", "-P",
		"(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))", "sAMAccountName")
	if err != nil {
		return nil, err
	}
	var users []string
	for _, mm := range samRE.FindAllSubmatch(out, -1) {
		u := strings.ToLower(string(mm[1]))
		if homeUserRE.MatchString(u) && !strings.HasSuffix(u, "$") && !noHome[u] {
			users = append(users, u)
		}
	}
	return users, nil
}

// makeHomes creates the home folders that don't exist yet. Existing ones
// are never changed or removed (a turned-off account keeps its files).
func (m *Manager) makeHomes(ctx context.Context, d *Domain, h HomesSettings, mount string) error {
	users, err := m.enabledUsers(ctx)
	if err != nil {
		return err
	}
	parent := HomesDataset(h.Pool)
	out, err := m.sysOutput(ctx, "zfs", "list", "-H", "-o", "name", "-d", "1", "-r", parent)
	if err != nil {
		return err
	}
	have := map[string]bool{}
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		have[strings.TrimSpace(l)] = true
	}
	names := m.names(ctx)
	var first error
	for _, u := range users {
		ds := parent + "/" + HomeName(d.NetBIOS, u)
		if have[ds] || zfs.ValidDatasetName(ds) != nil {
			continue
		}
		account := strings.ToUpper(d.NetBIOS) + `\` + u
		uid, err := names.UserID(account)
		if err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		gid, err := names.GroupID(strings.ToUpper(d.NetBIOS) + `\` + domainUsersGroup)
		if err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		args := []string{"create", "-o", "org.hardyos:home=" + account}
		if h.QuotaBytes > 0 {
			args = append(args, "-o", "quota="+strconv.FormatUint(h.QuotaBytes, 10))
		}
		if _, err := m.sysOutput(ctx, "zfs", append(args, ds)...); err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		p := filepath.Join(mount, HomeName(d.NetBIOS, u))
		if err := os.Lchown(p, int(uid), int(gid)); err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		if err := os.Chmod(p, 0o700); err != nil && first == nil {
			first = err
		}
		m.log().Info("home folder created", "account", account, "dataset", ds)
	}
	return first
}
