package nbstandby

import (
	"errors"
	"regexp"
	"strings"

	"golang.org/x/crypto/ssh"
)

// The VPS side (decision 421). HardyOS never runs a command of its choosing
// on the VPS: its one key is installed with `restrict` and a forced command
// that accepts exactly the verbs below (anything else, including what the
// client asks for, is refused), runs as the unprivileged user
// hardyos-standby, and reaches root only through sudo for exactly
// "<root script> <verb>". restore, fence and unfence are in sudoers, and
// accepted by the root script, only when the script was installed with
// --allow-handback; restore also needs a one-shot arm a person makes on the
// VPS (decision 427).
const (
	VerbStatus   = "status"
	VerbSnapshot = "snapshot"
	VerbRestore  = "restore"
	// VerbFence stops the VPS's netbird-server and marks it fenced (a
	// take-over while the VPS still answers); VerbUnfence undoes it.
	VerbFence   = "fence"
	VerbUnfence = "unfence"
)

// VPSUser is the account HardyOS's key may log in as.
const VPSUser = "hardyos-standby"

// Restore uploads carry these entries (the standby's databases with their
// write-ahead logs, and their checksums): nothing else is accepted.
var restoreEntries = []string{"SHA256SUMS", "GENERATION", "VERSION", "data/store.db", "data/idp.db", "data/events.db",
	"data/store.db-wal", "data/idp.db-wal", "data/events.db-wal"}

// ScriptSetup is what the VPS script is made from.
type ScriptSetup struct {
	Hostname  string // the NetBird server's name (vpn.example.net)
	PublicKey string // root's public key, authorized_keys format
	// From are the addresses (or prefixes) HardyOS connects from; empty
	// means no from= restriction (the key alone).
	From []string
}

// Validate checks the inputs before they go into a script.
func (s ScriptSetup) Validate() error {
	if !ValidHostname(s.Hostname) {
		return errors.New("set the NetBird server's name first")
	}
	pk, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(s.PublicKey))
	if err != nil || len(strings.TrimSpace(string(rest))) > 0 || pk.Type() != ssh.KeyAlgoED25519 {
		return errors.New("HardyOS hasn't made its SSH key yet")
	}
	return s.validateFrom()
}

// keyLine is the authorized_keys line. Every part is checked again here,
// whatever validated it before: it goes into a quoted heredoc of a script
// the administrator runs as root (security review N1).
func (s ScriptSetup) keyLine() (string, error) {
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(s.PublicKey))
	if err != nil || pk.Type() != ssh.KeyAlgoED25519 || strings.ContainsAny(strings.TrimRight(s.PublicKey, "\n"), "\r\n\x00") {
		return "", errors.New("HardyOS hasn't made its SSH key yet")
	}
	from, err := CanonicalFrom(s.From)
	if err != nil {
		return "", err
	}
	opts := `restrict,command="/usr/local/sbin/hardyos-netbird-standby"`
	if len(from) > 0 {
		for _, f := range from {
			if !fromRE.MatchString(f) {
				return "", errors.New("bad from= address")
			}
		}
		opts += `,from="` + strings.Join(from, ",") + `"`
	}
	if !ValidHostname(s.Hostname) {
		return "", errors.New("bad hostname")
	}
	line := opts + " " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk))) + " hardyos-standby@" + s.Hostname
	want := 2 // command="..."
	if len(from) > 0 {
		want = 4 // and from="..."
	}
	if strings.ContainsAny(line, "\n\r\x00'`$\\") || strings.Count(line, `"`) != want || !keyLineRE.MatchString(line) {
		return "", errors.New("the key line isn't safe to put in the VPS script")
	}
	return line, nil
}

// keyLineRE is the whole authorized_keys line: nothing outside it reaches
// the script.
var keyLineRE = regexp.MustCompile(`^restrict,command="/usr/local/sbin/hardyos-netbird-standby"(,from="[0-9A-Fa-f.:/,]+")? ssh-ed25519 [A-Za-z0-9+/=]+ hardyos-standby@[a-z0-9.-]+$`)

// Script is the shell script to run once on the VPS as root (again after a
// new key). It installs the user, its one key, the forced command, the root
// script and its sudo rule; it changes nothing about NetBird itself.
func Script(s ScriptSetup) (string, error) {
	if err := s.Validate(); err != nil {
		return "", err
	}
	line, err := s.keyLine()
	if err != nil {
		return "", err
	}
	// The other values in the script: a host name (lower-case letters,
	// digits, dots and dashes only) and fixed entry names.
	if !hostRE.MatchString(s.Hostname) {
		return "", errors.New("bad hostname")
	}
	return strings.NewReplacer("@@HOSTNAME@@", s.Hostname, "@@KEYLINE@@", line,
		"@@RESTORE_CASE@@", strings.Join(restoreEntries, "|")).Replace(scriptTemplate), nil
}
