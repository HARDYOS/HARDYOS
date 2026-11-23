// Package router finds this server's IPv4 default router and keeps the
// "this server is behind NAT: trust the router's address" setting
// (decision 441), shared by hardyd and hardyctl.
package router

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/store"
)

// SettingTrust is the settings key of the trusted router.
const SettingTrust = "auth.mfa.trust_router"

// ErrNoRouter: there's no default router with a known MAC address.
var ErrNoRouter = errors.New("this server has no default router with a known MAC address right now")

// Trusted is the router an administrator trusted, bound to its address and
// MAC address.
type Trusted struct {
	IP  string    `json:"ip"`
	MAC string    `json:"mac"`
	At  time.Time `json:"at"`
	By  string    `json:"by"`
}

// Matches reports whether t is the router at ip with mac.
func (t *Trusted) Matches(ip netip.Addr, mac string) bool {
	return t != nil && ip.IsValid() && mac != "" && t.IP == ip.String() && strings.EqualFold(t.MAC, mac)
}

// Paths of the kernel tables (tests change them).
var (
	routeFile = "/proc/net/route"
	arpFile   = "/proc/net/arp"
)

// Default is the IPv4 default gateway and its MAC address ("" when the
// kernel doesn't know it yet).
func Default() (netip.Addr, string) {
	f, err := os.Open(routeFile)
	if err != nil {
		return netip.Addr{}, ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fl := strings.Fields(sc.Text())
		if len(fl) < 3 || fl[1] != "00000000" {
			continue
		}
		// The gateway is printed as the kernel holds it in memory, in this
		// machine's byte order.
		w, err := strconv.ParseUint(fl[2], 16, 32)
		if err != nil || len(fl[2]) != 8 {
			continue
		}
		var a [4]byte
		binary.NativeEndian.PutUint32(a[:], uint32(w))
		if ip := netip.AddrFrom4(a); !ip.IsUnspecified() {
			return ip, MAC(ip)
		}
	}
	return netip.Addr{}, ""
}

// MAC is ip's hardware address from the ARP table.
func MAC(ip netip.Addr) string {
	f, err := os.Open(arpFile)
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fl := strings.Fields(sc.Text())
		if len(fl) >= 4 && fl[0] == ip.String() && fl[3] != "00:00:00:00:00:00" {
			return strings.ToLower(fl[3])
		}
	}
	return ""
}

// Load reads the trusted router (nil when off).
func Load(ctx context.Context, db *store.DB) *Trusted {
	v, err := db.GetSetting(ctx, SettingTrust)
	if err != nil || v == "" {
		return nil
	}
	var t Trusted
	if json.Unmarshal([]byte(v), &t) != nil || t.IP == "" || t.MAC == "" {
		return nil
	}
	return &t
}

// Trust saves ip/mac as the trusted router.
func Trust(ctx context.Context, db *store.DB, ip netip.Addr, mac, by string) (*Trusted, error) {
	if !ip.IsValid() || mac == "" {
		return nil, ErrNoRouter
	}
	t := &Trusted{IP: ip.String(), MAC: strings.ToLower(mac), At: time.Now().UTC(), By: by}
	b, _ := json.Marshal(t)
	return t, db.SetSetting(ctx, SettingTrust, string(b))
}

// Untrust turns the setting off.
func Untrust(ctx context.Context, db *store.DB) error {
	_, err := db.ExecContext(ctx, `DELETE FROM settings WHERE key = ?`, SettingTrust)
	return err
}
