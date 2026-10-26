package smb

import (
	"fmt"
	"sort"
	"strings"
	"unicode"
)

// Samba's ID ranges (docs/plans/file-sharing.md section 1): local users
// are 1000-2999, apps 30000-30999, NFS identities 31000-31999.
const (
	IDMapDefaultLow  = 3000
	IDMapDefaultHigh = 7999
	IDMapDomainLow   = 100000
	IDMapDomainHigh  = 999999
	// NobodyUID is the guest account's user ID (Debian's nobody).
	NobodyUID = 65534
)

// Snapshot names Previous Versions shows (section 2 of the contract):
// <dataset>@hardyos-auto-<kind>_<YYYY-MM-DD-HHMM>, UTC. Samba compiles
// shadow:snapprefix as a POSIX basic regular expression, so the group and
// alternation are written \( \| \).
const (
	snapPrefix    = `^hardyos-auto-\(hourly\|daily\|weekly\|monthly\)$`
	snapDelimiter = "_"
	snapFormat    = "_%Y-%m-%d-%H%M"
)

// confInput is everything smb.conf is made from.
type confInput struct {
	Domain     Domain
	ServerName string // this server's NetBIOS name
	Shares     []shareConf
	// HomesPath is where home folders are mounted ("" = no [homes]).
	HomesPath string
	Dirs      Dirs
	Port      int
}

// Dirs are Samba's state folders ("" = Samba's default).
type Dirs struct {
	Private, State, Cache, Lock, PID, NCALRPC, Log, Keytab string
}

// shareConf is one [share] section.
type shareConf struct {
	Name, Path, Comment string
	Valid, Read, Write  []string
	Invalid             []string
	Guest               bool
	Recycle             bool
	PreviousVersions    bool
	TimeMachine         bool
	TimeMachineMaxBytes uint64
}

// quoteList writes a Samba user list: every name quoted (domain names have
// spaces and backslashes).
func quoteList(names []string) string {
	q := make([]string, len(names))
	for i, n := range names {
		q[i] = `"` + n + `"`
	}
	return strings.Join(q, ", ")
}

// confSafe makes free text safe for a value: no line breaks, no
// substitutions (%), no quotes and never a trailing backslash (which would
// continue the line).
func confSafe(s string) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case unicode.IsControl(r), r == '%', r == '\\', r == '"':
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// sizeOption writes a byte count the way fruit:time machine max size reads
// it (whole megabytes at least).
func sizeOption(b uint64) string {
	const m = 1 << 20
	if b < m {
		b = m
	}
	return fmt.Sprintf("%dM", b/m)
}

func renderConf(in confInput) string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, "\t"+format+"\n", a...) }
	d := in.Domain
	nb := strings.ToUpper(d.NetBIOS)
	b.WriteString("# HardyOS file sharing (SMB). Written by hardyd-priv from the shared\n")
	b.WriteString("# folders and Control Panel > File Services: changes here are replaced.\n")
	b.WriteString("[global]\n")
	w("server role = member server")
	w("security = ads")
	w("workgroup = %s", nb)
	w("realm = %s", strings.ToUpper(d.Realm))
	w("netbios name = %s", in.ServerName)
	w("server string = HardyOS")
	if len(d.DCs) > 0 {
		// This server's own DC first (reached inside the host), then the
		// rest of the domain as DNS lists it.
		w("password server = %s *", strings.Join(d.DCs, " "))
	}
	w("kerberos method = secrets and keytab")
	w("dedicated keytab file = %s", or(in.Dirs.Keytab, "/etc/krb5.keytab"))
	w("winbind use default domain = no")
	w("winbind refresh tickets = yes")
	w("winbind offline logon = no")
	w("winbind enum users = no")
	w("winbind enum groups = no")
	w("idmap config * : backend = tdb")
	w("idmap config * : range = %d-%d", IDMapDefaultLow, IDMapDefaultHigh)
	w("idmap config %s : backend = rid", nb)
	w("idmap config %s : range = %d-%d", nb, IDMapDomainLow, IDMapDomainHigh)
	w("template shell = /usr/sbin/nologin")
	if in.HomesPath != "" {
		// %U is the account name as winbind gives it (lower case).
		w("template homedir = %s/%s.%%U", in.HomesPath, strings.ToLower(nb))
	} else {
		w("template homedir = /nonexistent")
	}
	w("disable netbios = yes")
	w("smb ports = %d", in.Port)
	w("server min protocol = SMB2_10")
	w("server signing = default")
	w("multicast dns register = no")
	w("load printers = no")
	w("printing = bsd")
	w("printcap name = /dev/null")
	w("disable spoolss = yes")
	w("unix extensions = no")
	w("map to guest = Bad User")
	w("guest account = nobody")
	guests := false
	for _, s := range in.Shares {
		guests = guests || s.Guest
	}
	if !guests {
		// Nobody needs to connect without an account.
		w("restrict anonymous = 2")
	}
	// Macs: Time Machine and resource forks (vfs_fruit, on every share).
	w("fruit:metadata = stream")
	w("fruit:model = MacSamba")
	w("fruit:posix_rename = yes")
	w("fruit:veto_appledouble = no")
	w("fruit:nfs_aces = no")
	w("fruit:wipe_intentionally_left_blank_rfork = yes")
	w("fruit:delete_empty_adfiles = yes")
	dirs := []struct{ opt, v string }{
		{"private dir", in.Dirs.Private}, {"state directory", in.Dirs.State},
		{"cache directory", in.Dirs.Cache}, {"lock directory", in.Dirs.Lock},
		{"pid directory", in.Dirs.PID}, {"ncalrpc dir", in.Dirs.NCALRPC},
	}
	for _, x := range dirs {
		if x.v != "" {
			w("%s = %s", x.opt, x.v)
		}
	}
	w("logging = file")
	if in.Dirs.Log != "" {
		w("log file = %s/log.%%m", in.Dirs.Log)
	} else {
		w("log file = /var/log/samba/log.%%m")
	}
	w("max log size = 5000")
	w("log level = 1")

	if in.HomesPath != "" {
		b.WriteString("\n[homes]\n")
		w("comment = Home folder")
		w("browseable = no")
		w("read only = no")
		w("valid users = %%S")
		w("guest ok = no")
		w("vfs objects = catia fruit streams_xattr acl_xattr")
		w("inherit acls = yes")
		w("map acl inherit = yes")
		w("create mask = 0600")
		w("directory mask = 0700")
	}

	shares := append([]shareConf(nil), in.Shares...)
	sort.Slice(shares, func(i, j int) bool { return strings.ToLower(shares[i].Name) < strings.ToLower(shares[j].Name) })
	for _, s := range shares {
		fmt.Fprintf(&b, "\n[%s]\n", s.Name)
		if c := confSafe(s.Comment); c != "" {
			w("comment = %s", c)
		}
		w("path = %s", s.Path)
		vfs := []string{"catia", "fruit", "streams_xattr"}
		if s.PreviousVersions {
			vfs = append(vfs, "shadow_copy2")
		}
		vfs = append(vfs, "acl_xattr")
		recycle := s.Recycle && !s.TimeMachine
		if recycle {
			vfs = append(vfs, "recycle")
		}
		w("vfs objects = %s", strings.Join(vfs, " "))
		w("read only = yes")
		w("valid users = %s", quoteList(s.Valid))
		if len(s.Read) > 0 {
			w("read list = %s", quoteList(s.Read))
		}
		if len(s.Write) > 0 {
			w("write list = %s", quoteList(s.Write))
		}
		if len(s.Invalid) > 0 {
			w("invalid users = %s", quoteList(s.Invalid))
		}
		if s.Guest {
			w("guest ok = yes")
		} else {
			w("guest ok = no")
		}
		w("access based share enum = yes")
		w("inherit acls = yes")
		w("map acl inherit = yes")
		w("hide files = /.recycle/.zfs/")
		w("veto files = /.hardyos*/")
		if recycle {
			// The same bins as the File Manager's: <netbios>.<user>, so a
			// name can only ever be one domain account's (shares.BinName).
			w("recycle:repository = .recycle/%s.%%U", strings.ToLower(nb))
			w("recycle:keeptree = yes")
			w("recycle:versions = yes")
			w("recycle:touch = yes")
			w("recycle:directory_mode = 0700")
			w("recycle:subdir_mode = 0700")
			w("recycle:exclude_dir = .recycle")
		}
		if s.PreviousVersions {
			// The dataset's root is its mount point; said outright so the
			// snapshot folder is found even if the share sits deeper.
			w("shadow:mountpoint = %s", s.Path)
			w("shadow:snapdir = .zfs/snapshot")
			w("shadow:snapprefix = %s", snapPrefix)
			w("shadow:delimiter = %s", snapDelimiter)
			w("shadow:format = %s", snapFormat)
			w("shadow:localtime = no")
			w("shadow:sort = desc")
		}
		if s.TimeMachine {
			w("fruit:time machine = yes")
			if s.TimeMachineMaxBytes > 0 {
				w("fruit:time machine max size = %s", sizeOption(s.TimeMachineMaxBytes))
			}
		}
	}
	return b.String()
}

// globalSection is the [global] part of a config (to tell whether winbind
// needs a restart or a reload is enough).
func globalSection(conf string) string {
	j := strings.Index(conf, "[global]")
	if j < 0 {
		return ""
	}
	rest := conf[j+len("[global]"):]
	if k := strings.Index(rest, "\n["); k >= 0 {
		return rest[:k]
	}
	return rest
}

func or(v, def string) string {
	if v != "" {
		return v
	}
	return def
}
