package san

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"regexp"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
)

// Secrets are one node's mutual CHAP credentials: User/Password is what the
// initiator proves to the target, MutualUser/MutualPassword what the target
// proves back. They never appear in the cluster log, in a command line or
// in a log line; root keeps them in a 0600 file of its own and hands a
// node's secrets only to that node (through the storage node's peer API).
type Secrets struct {
	User           string `json:"user"`
	Password       string `json:"password"`
	MutualUser     string `json:"mutualUser"`
	MutualPassword string `json:"mutualPassword"`
}

// SecretLen is the length of every generated CHAP secret.
const SecretLen = 24

const secretAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"

var (
	chapUserRE   = regexp.MustCompile(`^[A-Za-z0-9.:_-]{1,128}$`)
	chapSecretRE = regexp.MustCompile(`^[A-Za-z0-9]{12,64}$`)
)

// String keeps secrets out of logs and error messages.
func (s Secrets) String() string { return "CHAP{" + s.User + "/" + s.MutualUser + "}" }

// GoString implements fmt.GoStringer the same way.
func (s Secrets) GoString() string { return s.String() }

// Validate checks the credentials' form (they go into configfs and into
// open-iscsi's node records, so no quoting is ever needed).
func (s Secrets) Validate() error {
	if !chapUserRE.MatchString(s.User) || !chapUserRE.MatchString(s.MutualUser) {
		return errors.New("CHAP user names must be 1-128 letters, digits, '.', ':', '_' or '-'")
	}
	if !chapSecretRE.MatchString(s.Password) || !chapSecretRE.MatchString(s.MutualPassword) {
		return errors.New("CHAP secrets must be 12-64 letters or digits")
	}
	if s.Password == s.MutualPassword {
		return errors.New("the two CHAP secrets must differ")
	}
	return nil
}

// RandomSecret makes a SecretLen-character secret.
func RandomSecret() (string, error) {
	b := make([]byte, SecretLen)
	max := big.NewInt(int64(len(secretAlphabet)))
	for i := range b {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		b[i] = secretAlphabet[n.Int64()]
	}
	return string(b), nil
}

// NewSecrets makes fresh credentials for a node.
func NewSecrets(node cluster.NodeID) (Secrets, error) {
	a, err := RandomSecret()
	if err != nil {
		return Secrets{}, err
	}
	b, err := RandomSecret()
	if err != nil {
		return Secrets{}, err
	}
	for a == b {
		if b, err = RandomSecret(); err != nil {
			return Secrets{}, err
		}
	}
	return Secrets{User: "hc-" + string(node), Password: a, MutualUser: "hc-" + string(node) + "-target", MutualPassword: b}, nil
}

// chapFile is root's CHAP store: node -> secrets, plus the discovery
// credential under the empty node id.
type chapFile map[cluster.NodeID]Secrets

func parseCHAP(b []byte) (chapFile, error) {
	var f chapFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("reading the CHAP store: %w", err)
	}
	if f == nil {
		f = chapFile{}
	}
	return f, nil
}
