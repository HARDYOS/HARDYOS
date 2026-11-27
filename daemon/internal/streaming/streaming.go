// Package streaming is hardyd's side of game streaming in a VM (decisions
// 400-409, docs/plans/streaming.md): the Sunshine account HardyOS made
// (sealed at rest) and a small client for Sunshine's API that pairs and
// unpairs Moonlight devices.
//
// hardyd talks to Sunshine over the home network, at the address root
// verified (the server's ARP table for the VM's MAC, never what the guest
// says), and only over TLS with the certificate root made for that VM
// pinned: a wrong address, or anything else answering there, gets no
// password and no PIN.
package streaming

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/ports"
	"github.com/hardyos/hardyos/daemon/internal/secretbox"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

// KeyPurpose is the secretbox purpose of Sunshine passwords.
const KeyPurpose = "vm-streaming"

// ErrNoAccount: HardyOS has no Sunshine account for the VM.
var ErrNoAccount = errors.New("HardyOS has no Sunshine account for this VM")

const passwordAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"

// NewPassword makes a Sunshine password: 24 letters and digits (about 140
// bits), which root accepts and which needs no quoting anywhere.
func NewPassword() (string, error) {
	b := make([]byte, 24)
	max := big.NewInt(int64(len(passwordAlphabet)))
	for i := range b {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		b[i] = passwordAlphabet[n.Int64()]
	}
	return string(b), nil
}

// Store keeps the accounts (table vm_streaming).
type Store struct {
	DB   *store.DB
	Keys secretbox.Source
}

func aad(vm string) []byte { return []byte("vm_streaming:" + vm) }

// Save keeps a VM's account, replacing one from a VM of the same name.
func (s *Store) Save(ctx context.Context, vm, user, password string) error {
	k, err := s.Keys.Key(ctx, KeyPurpose)
	if err != nil {
		return err
	}
	sealed, err := secretbox.Seal(k, []byte(password), aad(vm))
	if err != nil {
		return err
	}
	_, err = s.DB.ExecContext(ctx, `INSERT INTO vm_streaming (vm_id, sunshine_user, password_sealed, created_at) VALUES (?, ?, ?, ?)
		ON CONFLICT(vm_id) DO UPDATE SET sunshine_user = excluded.sunshine_user, password_sealed = excluded.password_sealed,
		created_at = excluded.created_at, revealed_at = ''`, vm, user, sealed, store.Now())
	return err
}

// Account is a VM's Sunshine account.
type Account struct {
	User       string
	Password   string
	RevealedAt string
}

// Get opens a VM's account.
func (s *Store) Get(ctx context.Context, vm string) (*Account, error) {
	var a Account
	var sealed []byte
	err := s.DB.QueryRowContext(ctx, `SELECT sunshine_user, password_sealed, revealed_at FROM vm_streaming WHERE vm_id = ?`, vm).Scan(&a.User, &sealed, &a.RevealedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoAccount
	}
	if err != nil {
		return nil, err
	}
	k, err := s.Keys.Key(ctx, KeyPurpose)
	if err != nil {
		return nil, err
	}
	pw, err := secretbox.Open(k, sealed, aad(vm))
	if err != nil {
		return nil, err
	}
	a.Password = string(pw)
	return &a, nil
}

// Has reports whether there's an account (without opening it).
func (s *Store) Has(ctx context.Context, vm string) (bool, string) {
	var at string
	err := s.DB.QueryRowContext(ctx, `SELECT revealed_at FROM vm_streaming WHERE vm_id = ?`, vm).Scan(&at)
	return err == nil, at
}

// Revealed records that an administrator looked at the password.
func (s *Store) Revealed(ctx context.Context, vm string) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE vm_streaming SET revealed_at = ? WHERE vm_id = ?`, store.Now(), vm)
	return err
}

// Delete forgets a VM's account (the VM was deleted).
func (s *Store) Delete(ctx context.Context, vm string) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM vm_streaming WHERE vm_id = ?`, vm)
	return err
}

// Target is one VM's Sunshine.
type Target struct {
	// Address is the VM's verified IPv4 address (from root).
	Address string
	// CertSHA256 pins Sunshine's certificate (hex SHA-256 of its DER).
	CertSHA256 string
	User       string
	Password   string
	// WebPort is Sunshine's web UI and API port in the VM (its port set's,
	// decision 506; 0: the standard one).
	WebPort int
}

// webPort is where t's Sunshine answers.
func (c *Client) webPort(t Target) int {
	switch {
	case c.Port != 0:
		return c.Port
	case t.WebPort != 0:
		return t.WebPort
	}
	return ports.SunshineWebUI
}

// Client calls Sunshine's API.
type Client struct {
	// Timeout per call (default 10 s).
	Timeout time.Duration
	// AllowLoopback lets tests use 127.0.0.1; Port replaces Sunshine's
	// web UI port (tests).
	AllowLoopback bool
	Port          int
}

// Client errors.
var (
	ErrUnreachable = errors.New("Sunshine isn't answering in the VM (is the VM running and Sunshine installed?)")
	ErrPin         = errors.New("Sunshine's certificate isn't the one HardyOS made for this VM; nothing was sent")
	ErrAuth        = errors.New("Sunshine refused HardyOS's account (was its password changed in the VM?)")
)

type pinError struct{}

func (pinError) Error() string { return ErrPin.Error() }

func (c *Client) http(t Target) (*http.Client, string, error) {
	addr, err := netip.ParseAddr(t.Address)
	if err != nil || !addr.Is4() || addr.IsUnspecified() || addr.IsMulticast() || (addr.IsLoopback() && !c.AllowLoopback) || (!addr.IsPrivate() && !addr.IsLoopback()) {
		return nil, "", fmt.Errorf("%q isn't a VM address on the home network", t.Address)
	}
	want, err := hex.DecodeString(t.CertSHA256)
	if err != nil || len(want) != sha256.Size {
		return nil, "", errors.New("no certificate to pin for this VM's Sunshine")
	}
	port := c.webPort(t)
	if port <= 0 || port > 65535 {
		return nil, "", errors.New("bad Sunshine port")
	}
	timeout := c.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	tr := &http.Transport{
		Proxy: nil,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			// The certificate is self-signed by design (root made it for
			// this VM); what's checked is that it's exactly that one.
			InsecureSkipVerify: true, //nolint:gosec // pinned below
			VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
				if len(raw) == 0 {
					return pinError{}
				}
				got := sha256.Sum256(raw[0])
				if subtle.ConstantTimeCompare(got[:], want) != 1 {
					return pinError{}
				}
				return nil
			},
		},
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: timeout,
		TLSHandshakeTimeout:   timeout,
	}
	return &http.Client{
		Transport: tr, Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, "https://" + netip.AddrPortFrom(addr, uint16(port)).String(), nil
}

func (c *Client) do(ctx context.Context, t Target, method, path string, body, out any) error {
	hc, base, err := c.http(t)
	if err != nil {
		return err
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, rd)
	if err != nil {
		return err
	}
	req.SetBasicAuth(t.User, t.Password)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	// No Origin or Referer: Sunshine's CSRF check applies to browsers only.
	res, err := hc.Do(req)
	if err != nil {
		var pe pinError
		if errors.As(err, &pe) {
			return ErrPin
		}
		return ErrUnreachable
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return ErrUnreachable
	}
	switch {
	case res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden:
		return ErrAuth
	case res.StatusCode >= 300 && res.StatusCode < 400:
		return errors.New("Sunshine has no account yet (it sends people to its welcome page); its setup in the VM didn't finish")
	case res.StatusCode != http.StatusOK:
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(b, &e)
		if msg := clip(e.Error); msg != "" {
			if r := []rune(msg); len(r) > 200 {
				msg = string(r[:200])
			}
			return fmt.Errorf("Sunshine said: %s", msg)
		}
		return fmt.Errorf("Sunshine answered %d", res.StatusCode)
	}
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			return fmt.Errorf("Sunshine's answer can't be read: %w", err)
		}
	}
	return nil
}

// configKeyRE: a key of Sunshine's settings file.
var configKeyRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// configMeta are what Sunshine's settings answer carries besides its
// settings (never written back).
var configMeta = map[string]bool{"status": true, "platform": true, "version": true, "restart_supported": true, "error": true}

// config reads Sunshine's settings (its sunshine.conf, key by key).
func (c *Client) config(ctx context.Context, t Target) (map[string]string, error) {
	var raw map[string]json.RawMessage
	if err := c.do(ctx, t, http.MethodGet, "/api/config", nil, &raw); err != nil {
		return nil, err
	}
	out := map[string]string{}
	for k, v := range raw {
		if configMeta[k] || !configKeyRE.MatchString(k) {
			continue
		}
		var s string
		if json.Unmarshal(v, &s) != nil {
			continue // only the file's own values, which are strings
		}
		if len(s) > 4096 || strings.ContainsAny(s, "\r\n") {
			return nil, errors.New("Sunshine's settings can't be read safely")
		}
		out[k] = s
	}
	if len(out) > 512 {
		return nil, errors.New("Sunshine's settings are too many to keep")
	}
	return out, nil
}

// BasePort is the base port Sunshine in the VM uses (its `port` setting;
// the standard one when unset).
func (c *Client) BasePort(ctx context.Context, t Target) (int, error) {
	cfg, err := c.config(ctx, t)
	if err != nil {
		return 0, err
	}
	v, ok := cfg["port"]
	if !ok || v == "" {
		return ports.SunshineHTTP, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 || n > 65535 {
		return 0, fmt.Errorf("Sunshine's port setting %q isn't a port", clip(v))
	}
	return n, nil
}

// SetBasePort gives Sunshine in the VM a new base port (decision 506):
// its settings are read, written back with only `port` changed (every
// other setting as it is: Sunshine writes the file from what it is
// given) and Sunshine restarts. Its web UI is then at the new port set's
// own port; the caller waits for it there.
func (c *Client) SetBasePort(ctx context.Context, t Target, base int) error {
	if _, ok := ports.StreamingSlotOfBase(base); !ok {
		return errors.New("that isn't one of HardyOS's streaming port sets")
	}
	cfg, err := c.config(ctx, t)
	if err != nil {
		return err
	}
	if base == ports.SunshineHTTP {
		delete(cfg, "port")
	} else {
		cfg["port"] = strconv.Itoa(base)
	}
	if err := c.do(ctx, t, http.MethodPost, "/api/config", cfg, nil); err != nil {
		return err
	}
	// Sunshine answers and then restarts: a connection it drops on the
	// way is the restart itself.
	if err := c.do(ctx, t, http.MethodPost, "/api/restart", map[string]string{}, nil); err != nil && !errors.Is(err, ErrUnreachable) {
		return err
	}
	return nil
}

// Device is a paired Moonlight device.
type Device struct {
	Name    string `json:"name"`
	UUID    string `json:"uuid"`
	Enabled bool   `json:"enabled"`
}

// Pending is a Moonlight device waiting for its PIN.
type Pending struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Address string `json:"address"`
}

var (
	pairingIDRE = regexp.MustCompile(`^[0-9a-f]{32}$`)
	pinRE       = regexp.MustCompile(`^[0-9]{4}$`)
	deviceRE    = regexp.MustCompile(`^[\p{L}\p{N} ._'()-]{1,64}$`)
	clientIDRE  = regexp.MustCompile(`^[0-9A-Fa-f-]{8,64}$`)
)

// Valid checks pairing input (also the API's quick check).
func ValidPairing(pairingID, pin, name string) error {
	switch {
	case !pairingIDRE.MatchString(pairingID):
		return errors.New("pick the device that's waiting to pair")
	case !pinRE.MatchString(pin):
		return errors.New("the PIN is the 4 digits Moonlight shows")
	case !deviceRE.MatchString(name):
		return errors.New("give the device a name of up to 64 letters, digits and spaces")
	}
	return nil
}

// ValidClientID checks a paired device's id.
func ValidClientID(id string) bool { return clientIDRE.MatchString(id) }

// Devices lists the paired devices.
func (c *Client) Devices(ctx context.Context, t Target) ([]Device, error) {
	var out struct {
		NamedCerts []struct {
			Name    string `json:"name"`
			UUID    string `json:"uuid"`
			Enabled *bool  `json:"enabled"`
		} `json:"named_certs"`
	}
	if err := c.do(ctx, t, http.MethodGet, "/api/clients/list", nil, &out); err != nil {
		return nil, err
	}
	devs := []Device{}
	for _, n := range out.NamedCerts {
		if len(devs) >= 256 {
			break
		}
		d := Device{Name: clip(n.Name), UUID: n.UUID, Enabled: n.Enabled == nil || *n.Enabled}
		if !ValidClientID(d.UUID) {
			continue
		}
		devs = append(devs, d)
	}
	return devs, nil
}

// Waiting lists devices waiting for their PIN.
func (c *Client) Waiting(ctx context.Context, t Target) ([]Pending, error) {
	var out struct {
		Pairings []Pending `json:"pairings"`
	}
	if err := c.do(ctx, t, http.MethodGet, "/api/pin", nil, &out); err != nil {
		return nil, err
	}
	ps := []Pending{}
	for _, p := range out.Pairings {
		if !pairingIDRE.MatchString(p.ID) || len(ps) >= 64 {
			continue
		}
		ps = append(ps, Pending{ID: p.ID, Name: clip(p.Name), Address: clip(p.Address)})
	}
	return ps, nil
}

// Pair gives Sunshine the PIN Moonlight shows for a waiting device.
func (c *Client) Pair(ctx context.Context, t Target, pairingID, pin, name string) error {
	if err := ValidPairing(pairingID, pin, name); err != nil {
		return err
	}
	var out struct {
		Status json.RawMessage `json:"status"`
	}
	if err := c.do(ctx, t, http.MethodPost, "/api/pin", map[string]string{"pairing_id": pairingID, "pin": pin, "name": name}, &out); err != nil {
		return err
	}
	if !truthy(out.Status) {
		return errors.New("Sunshine didn't accept the PIN (check the 4 digits Moonlight shows, and that it's still waiting)")
	}
	return nil
}

// Unpair removes a paired device.
func (c *Client) Unpair(ctx context.Context, t Target, uuid string) error {
	if !ValidClientID(uuid) {
		return errors.New("that isn't a paired device")
	}
	var out struct {
		Status json.RawMessage `json:"status"`
	}
	if err := c.do(ctx, t, http.MethodPost, "/api/clients/unpair", map[string]string{"uuid": uuid}, &out); err != nil {
		return err
	}
	if !truthy(out.Status) {
		return errors.New("Sunshine doesn't know that device")
	}
	return nil
}

func truthy(raw json.RawMessage) bool {
	var b bool
	if json.Unmarshal(raw, &b) == nil {
		return b
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		v, _ := strconv.ParseBool(s)
		return v
	}
	return false
}

func clip(s string) string {
	r := []rune(s)
	if len(r) > 128 {
		r = r[:128]
	}
	out := make([]rune, 0, len(r))
	for _, c := range r {
		if c >= 0x20 && c != 0x7f {
			out = append(out, c)
		}
	}
	return string(out)
}
