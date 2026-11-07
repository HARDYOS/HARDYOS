package witness

import (
	"bytes"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"text/template"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
)

// The install script (like mail's VPS relay script): run as root on a
// plain Ubuntu VPS that is in the same NetBird network. It downloads the
// witness binary from a member over NetBird (curl pins the member's key;
// the file's SHA-256 is checked), installs a systemd unit with a dynamic
// user and a strict sandbox, listening on the NetBird address only, and
// joins with the code it carries (handed to the service as a systemd
// credential, never on a command line). The script is as secret as its
// code: valid once, for 30 minutes.

//go:embed install.sh.tmpl
var scriptTmpl string

var tmpl = template.Must(template.New("witness").Parse(scriptTmpl))

// ScriptMember is a member the script may download from and join through.
type ScriptMember struct {
	NetBird netip.Addr
	Pin     string // hex SHA-256 of its key
}

// ScriptParams fill the script.
type ScriptParams struct {
	Cluster   cluster.ClusterID
	Node      cluster.NodeID
	Code      string
	Members   []ScriptMember
	BinarySHA string // hex SHA-256 of the hardyos-witness binary
	Version   string
	Port      int
}

var hexRE = regexp.MustCompile(`^[0-9a-f]{64}$`)
var codeRE = regexp.MustCompile(`^[A-Z2-7-]{20,40}$`)
var versionRE = regexp.MustCompile(`^[A-Za-z0-9.+_-]{1,64}$`)

type scriptMember struct {
	Address string
	Pin     string
	PinB64  string
}

// Script renders the install script. Every value is checked against a
// strict pattern before it is put into shell text.
func Script(p ScriptParams) ([]byte, error) {
	if !hexRE.MatchString(p.BinarySHA) {
		return nil, errors.New("invalid binary checksum")
	}
	if !codeRE.MatchString(p.Code) {
		return nil, errors.New("invalid join code")
	}
	if !versionRE.MatchString(p.Version) {
		return nil, errors.New("invalid version")
	}
	if p.Port == 0 {
		p.Port = cluster.Port
	}
	if len(p.Members) == 0 {
		return nil, errors.New("no member on NetBird to download from")
	}
	var ms []scriptMember
	for _, m := range p.Members {
		if !m.NetBird.IsValid() || !hexRE.MatchString(m.Pin) {
			return nil, errors.New("invalid member")
		}
		raw, _ := hex.DecodeString(m.Pin)
		ms = append(ms, scriptMember{Address: netip.AddrPortFrom(m.NetBird, uint16(p.Port)).String(), Pin: m.Pin,
			PinB64: base64.StdEncoding.EncodeToString(raw)})
	}
	var b bytes.Buffer
	err := tmpl.Execute(&b, map[string]any{
		"Cluster": string(p.Cluster), "Node": string(p.Node), "Code": p.Code, "Members": ms,
		"SHA": p.BinarySHA, "Version": p.Version, "Port": fmt.Sprint(p.Port),
	})
	return b.Bytes(), err
}
