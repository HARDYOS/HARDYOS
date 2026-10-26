package install

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
)

// LiveMarker exists only on the live ISO. hardyd-priv registers the install
// operations, and hardyd serves the installer, only when it is present.
const LiveMarker = "/etc/hardyos/live-installer"

// CodeFile holds the one-time install code (root:hardyd 0640).
const CodeFile = "/run/hardyos/install-code"

// IsLive reports whether this system is the live installer.
func IsLive(root string) bool {
	_, err := os.Stat(filepath.Join(root, LiveMarker))
	return err == nil
}

// codeAlphabet avoids look-alike characters (0/O, 1/I/L).
const codeAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

// NewCode returns a random code like "K7QM-4TXP" (about 40 bits).
func NewCode() (string, error) {
	var b strings.Builder
	for i := 0; i < 8; i++ {
		if i == 4 {
			b.WriteByte('-')
		}
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(codeAlphabet))))
		if err != nil {
			return "", err
		}
		b.WriteByte(codeAlphabet[n.Int64()])
	}
	return b.String(), nil
}

// NormalizeCode uppercases a typed code and drops spaces and dashes.
func NormalizeCode(s string) string {
	s = strings.ToUpper(s)
	return strings.Map(func(r rune) rune {
		if r == '-' || r == ' ' {
			return -1
		}
		return r
	}, s)
}

// CodesMatch compares a typed code with the real one in constant time.
func CodesMatch(typed, real string) bool {
	a, b := NormalizeCode(typed), NormalizeCode(real)
	return len(a) == 8 && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// PublishCode writes the code for hardyd and shows it on the console: in the
// login banner (/etc/issue.d, read by agetty; the live root is writable) and the message of the day.
func PublishCode(root, code string, gid int) error {
	path := filepath.Join(root, CodeFile)
	if err := os.WriteFile(path, []byte(code+"\n"), 0o640); err != nil {
		return err
	}
	if gid >= 0 {
		if err := os.Chown(path, 0, gid); err != nil {
			return err
		}
	}
	banner := fmt.Sprintf(`
  =====================================================
   HardyOS installer

   Open the address above in a browser on another
   computer and enter this code:  %s
  =====================================================

`, code)
	motd := fmt.Sprintf("\n  HardyOS installer: open https://<this server's address> in a browser\n  and enter the code %s\n\n", code)
	for p, content := range map[string]string{
		"/etc/issue.d/50-hardyos-installer.issue": banner, // read by agetty after /etc/issue
		"/run/motd.d/50-hardyos-installer":        motd,
	} {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			return err
		}
	}
	return nil
}
