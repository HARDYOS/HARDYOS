package cloudbackup

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/hardyos/hardyos/daemon/internal/rootfile"
)

// Every snapshot carries the server's install id (server=<id>, decision
// 179). Several servers can share a bucket; people only ever see and
// restore this server's versions, administrators see the others labelled.
// The id is made at the first backup and follows a settings restore (the
// restored server carries on as the one that made the versions).

// ServerIDFile holds the id in root's backup state directory.
const ServerIDFile = "server-id"

var serverIDRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

// ServerID is this server's install id (made on first use).
func (r *Root) ServerID() string {
	r.idMu.Lock()
	defer r.idMu.Unlock()
	if r.serverID != "" {
		return r.serverID
	}
	p := filepath.Join(r.dir(), ServerIDFile)
	if b, err := rootfile.ReadFile(p); err == nil && serverIDRE.MatchString(strings.TrimSpace(string(b))) {
		r.serverID = strings.TrimSpace(string(b))
		return r.serverID
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		r.log().Warn("cloud backup: reading the server's id", "err", err)
	}
	id := randomID(16)
	if err := rootfile.WriteInRootDir(p, []byte(id+"\n"), 0o600, 0o700); err != nil {
		r.log().Warn("cloud backup: saving the server's id", "err", err)
	}
	r.serverID = id
	return id
}

// adoptServerID makes id this server's (a settings restore).
func (r *Root) adoptServerID(id string) error {
	if !serverIDRE.MatchString(id) {
		return nil // a version from before ids: keep ours
	}
	r.idMu.Lock()
	defer r.idMu.Unlock()
	if err := rootfile.WriteInRootDir(filepath.Join(r.dir(), ServerIDFile), []byte(id+"\n"), 0o600, 0o700); err != nil {
		return err
	}
	r.serverID = id
	return nil
}

// ours reports whether snap was made by this server.
func (r *Root) ours(s *Snapshot) bool { return s.Tag("server") == r.ServerID() }
