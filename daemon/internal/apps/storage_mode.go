package apps

// Cluster storage hints (Phase 8 part B, decision 341). On a cluster an
// app's data lives on the storage node, either as an NFS dataset or as a
// block volume (a zvol LUN with ext4 or xfs, exclusive to the app's node,
// like a VM disk). Databases are safest on block storage: SQLite and
// database servers rely on fsync, byte-range locks and mmap behaving like a
// local disk, which a single exclusive NFSv4.2 client mostly but not
// entirely gives. So an app that declares a database, or whose compose
// file runs a known database image, defaults to block mode; everything
// else (media, documents: files shared folders and other tools also read)
// defaults to NFS. The administrator can switch an app either way.

import (
	"regexp"
	"strings"
)

// Storage modes (cluster.StorageMode's values).
const (
	StorageModeNFS   = "nfs"
	StorageModeBlock = "block"
)

// StorageHints is the manifest's "storage" object.
type StorageHints struct {
	// Mode forces a default: "nfs" or "block". Empty: decided from
	// Database and the compose file's images.
	Mode string `json:"mode,omitempty"`
	// Database names the database the app keeps in its data folder:
	// postgres, mysql, mariadb, mongodb, sqlite, or other. Any value makes
	// block mode the default.
	Database string `json:"database,omitempty"`
	// BlockSizeGB is the block volume's suggested size (sparse; default 64).
	BlockSizeGB int `json:"blockSizeGB,omitempty"`
}

var databases = map[string]bool{"postgres": true, "mysql": true, "mariadb": true, "mongodb": true, "sqlite": true, "other": true}

func (h *StorageHints) validate(p *Problems) {
	if h == nil {
		return
	}
	if h.Mode != "" && h.Mode != StorageModeNFS && h.Mode != StorageModeBlock {
		p.addf("storage.mode must be nfs or block")
	}
	if h.Database != "" && !databases[h.Database] {
		p.addf("storage.database must be postgres, mysql, mariadb, mongodb, sqlite or other")
	}
	if h.BlockSizeGB < 0 || h.BlockSizeGB > 16384 {
		p.addf("storage.blockSizeGB must be 1 to 16384")
	}
}

// databaseImageRE matches the repository part of images that are database
// servers keeping their files in a bind mount.
var databaseImageRE = regexp.MustCompile(`(^|/)(postgres|postgresql|postgis|mysql|mariadb|mongo|mongodb|timescaledb|influxdb|clickhouse-server|couchdb|cockroach|redis-stack-server)(:|@|$)|(^|/)immich-app/postgres(:|@|$)`)

var imageLineRE = regexp.MustCompile(`(?m)^\s*image:\s*["']?([^"'\s#]+)`)

// DatabaseImages lists the compose file's images that are database
// servers.
func DatabaseImages(compose []byte) []string {
	var out []string
	for _, m := range imageLineRE.FindAllSubmatch(compose, -1) {
		img := strings.ToLower(string(m[1]))
		if databaseImageRE.MatchString(img) {
			out = append(out, img)
		}
	}
	return out
}

// DefaultStorageMode is an app's cluster data mode when the administrator
// hasn't chosen one, and why.
func DefaultStorageMode(m Manifest, compose []byte) (mode, reason string) {
	if m.Storage != nil {
		switch {
		case m.Storage.Mode != "":
			return m.Storage.Mode, "the app's package asks for it"
		case m.Storage.Database != "":
			return StorageModeBlock, "the app keeps a " + m.Storage.Database + " database"
		}
	}
	if imgs := DatabaseImages(compose); len(imgs) > 0 {
		return StorageModeBlock, "the app runs a database server (" + imgs[0] + ")"
	}
	return StorageModeNFS, "the app keeps plain files"
}
