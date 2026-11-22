package nbstandby

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Remote runs one of the VPS's forced-command verbs: stdin (restore only)
// goes to it, its output to stdout.
type Remote interface {
	Run(ctx context.Context, verb string, stdin io.Reader, stdout io.Writer) error
}

// SSHTarget is where the VPS is and how root logs in.
type SSHTarget struct {
	Host    string // host name or address (no port)
	Port    int
	User    string
	HostKey ssh.PublicKey // pinned: nothing else is accepted
	Signer  ssh.Signer
	// Dial connects (tests: in-process); default net.Dialer.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

var userRE = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// ValidVPSHost reports whether h is a host name or an IP address.
func ValidVPSHost(h string) bool {
	if a, err := netip.ParseAddr(h); err == nil {
		return a.Zone() == "" && !a.IsUnspecified() && !a.IsMulticast()
	}
	return ValidHostname(h)
}

// ValidVPSUser reports whether u is a plain login name.
func ValidVPSUser(u string) bool { return userRE.MatchString(u) }

// ParseHostKey reads a host key as `ssh-keyscan` or the VPS script prints
// it ("ssh-ed25519 AAAA… [comment]", optionally with a host name first).
func ParseHostKey(s string) (ssh.PublicKey, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("paste the VPS's host key")
	}
	if pk, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(s)); err == nil && len(strings.TrimSpace(string(rest))) == 0 {
		return checkHostKeyType(pk)
	}
	// known_hosts form: "host ssh-ed25519 AAAA…"
	if _, _, pk, _, rest, err := ssh.ParseKnownHosts([]byte(s)); err == nil && len(strings.TrimSpace(string(rest))) == 0 {
		return checkHostKeyType(pk)
	}
	return nil, errors.New("that isn't an SSH host key (expected a line like: ssh-ed25519 AAAA…)")
}

func checkHostKeyType(pk ssh.PublicKey) (ssh.PublicKey, error) {
	switch pk.Type() {
	case ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521, ssh.KeyAlgoRSA:
		return pk, nil
	}
	return nil, fmt.Errorf("host key type %s isn't accepted", pk.Type())
}

// NewKey makes root's ed25519 key pair: the private key's seed and the
// public half in authorized_keys form.
func NewKey() (seed []byte, public string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", err
	}
	spk, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, "", err
	}
	return priv.Seed(), strings.TrimSpace(string(ssh.MarshalAuthorizedKey(spk))), nil
}

// SignerFromSeed turns a stored seed back into a signer.
func SignerFromSeed(seed []byte) (ssh.Signer, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("the stored key is damaged")
	}
	return ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(seed))
}

func marshalKey(pk ssh.PublicKey) []byte { return ssh.MarshalAuthorizedKey(pk) }

// Fingerprint is a key's SHA-256 fingerprint as OpenSSH prints it.
func Fingerprint(pk ssh.PublicKey) string { return ssh.FingerprintSHA256(pk) }

// maxStderr bounds what the VPS may say about a failure.
const maxStderr = 4 << 10

type limitedBuffer struct {
	b bytes.Buffer
	n int
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if room := l.n - l.b.Len(); room > 0 {
		l.b.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

// Run implements Remote over SSH. Only the verbs are ever sent; the VPS
// runs its forced command whatever is asked, so the verb is a request it
// checks again.
func (t SSHTarget) Run(ctx context.Context, verb string, stdin io.Reader, stdout io.Writer) error {
	switch verb {
	case VerbStatus, VerbSnapshot, VerbRestore:
	default:
		return fmt.Errorf("unknown verb %q", verb)
	}
	if t.HostKey == nil || t.Signer == nil {
		return errors.New("the VPS connection isn't set up")
	}
	if !ValidVPSHost(t.Host) || !ValidVPSUser(t.User) || t.Port < 1 || t.Port > 65535 {
		return errors.New("the VPS address isn't valid")
	}
	cfg := &ssh.ClientConfig{
		User:              t.User,
		Auth:              []ssh.AuthMethod{ssh.PublicKeys(t.Signer)},
		HostKeyCallback:   ssh.FixedHostKey(t.HostKey),
		HostKeyAlgorithms: hostAlgos(t.HostKey),
		Timeout:           20 * time.Second,
	}
	addr := net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
	dial := t.Dial
	if dial == nil {
		d := &net.Dialer{Timeout: 20 * time.Second}
		dial = d.DialContext
	}
	conn, err := dial(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("can't reach the VPS at %s: %v", addr, clipErr(err))
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second)) // handshake
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		conn.Close()
		if strings.Contains(err.Error(), "host key mismatch") {
			return errors.New("the VPS's host key isn't the one saved in HardyOS: someone may be in between, or the VPS was reinstalled (paste its new host key)")
		}
		return fmt.Errorf("SSH to the VPS failed: %v", clipErr(err))
	}
	_ = conn.SetDeadline(time.Time{})
	client := ssh.NewClient(c, chans, reqs)
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("SSH session: %v", clipErr(err))
	}
	defer sess.Close()
	var stderr limitedBuffer
	stderr.n = maxStderr
	sess.Stdout = stdout
	sess.Stderr = &stderr
	if stdin != nil {
		sess.Stdin = stdin
	}
	if err := sess.Run(verb); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		msg := strings.TrimSpace(stderr.b.String())
		if msg == "" {
			msg = clipErr(err)
		}
		return &VPSError{Msg: clip(msg, 300)}
	}
	return nil
}

// hostAlgos asks only for the pinned key's own algorithm (RSA keys by
// their SHA-2 signatures, never SHA-1).
func hostAlgos(pk ssh.PublicKey) []string {
	if pk.Type() == ssh.KeyAlgoRSA {
		return []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}
	}
	return []string{pk.Type()}
}

// VPSError is what the VPS's script said when a verb failed.
type VPSError struct{ Msg string }

func (e *VPSError) Error() string { return "the VPS said: " + e.Msg }
