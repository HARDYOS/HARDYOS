// Command hardyctl is the HardyOS command-line tool for scripting and recovery.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/boot"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/store"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
	"github.com/hardyos/hardyos/daemon/internal/version"
)

const usage = `hardyctl: manage a HardyOS system

Usage:
  hardyctl [flags] <command> [args]

Commands:
  version                    print the hardyctl version
  status                     show hardyd health and version
  priv-ping                  check the root helper directly (run as root)

Recovery (run as root on the server; works even if hardyd is down):
  reset-password <username>  set a new password, re-enable the account, sign out its sessions
  create-admin <username>    add a new administrator (if every admin is locked out)

Boot (run as root):
  boot-list                  list boot environments
  boot-sync [--reinstall]    copy kernels to the boot disks and rewrite the boot menu
                             (runs automatically after kernel and initramfs updates)

Apps:
  app-pack [-o file] <folder>  build a .hardyapp package from a folder (hardyapp.json,
                               compose.yaml, icon); see docs/apps.md
  app-check <file|folder>      check a package and show what installing it asks for

Flags:
`

func main() {
	api := flag.String("api", envOr("HARDYOS_API", "https://127.0.0.1"), "hardyd base URL")
	socket := flag.String("socket", priv.DefaultSocket, "hardyd-priv socket (for priv-ping)")
	dbPath := flag.String("db", store.DefaultPath, "hardyd database (for recovery commands)")
	pwStdin := flag.Bool("password-stdin", false, "read the new password from stdin instead of prompting")
	flag.Usage = func() {
		fmt.Fprint(os.Stderr, usage)
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(2)
	}

	var err error
	switch cmd, args := flag.Arg(0), flag.Args()[1:]; cmd {
	case "version":
		fmt.Printf("hardyctl %s (%s)\n", version.Version, version.Commit)
	case "status":
		err = status(*api)
	case "priv-ping":
		err = privPing(*socket)
	case "reset-password":
		err = recovery(*dbPath, args, *pwStdin, false)
	case "create-admin":
		err = recovery(*dbPath, args, *pwStdin, true)
	case "app-pack":
		err = appPack(args)
	case "app-check":
		err = appCheck(args)
	case "boot-list":
		err = bootList()
	case "boot-sync":
		err = bootSync(args)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		flag.Usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func status(base string) error {
	client := &http.Client{Timeout: 5 * time.Second}
	if u, err := url.Parse(base); err == nil {
		if ip := net.ParseIP(u.Hostname()); (ip != nil && ip.IsLoopback()) || u.Hostname() == "localhost" {
			// The local self-signed certificate isn't trusted; we're talking to ourselves.
			client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec
		}
	}
	for _, p := range []string{"/api/v1/health", "/api/v1/version"} {
		res, err := client.Get(strings.TrimRight(base, "/") + p)
		if err != nil {
			return err
		}
		body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		res.Body.Close()
		if res.StatusCode != http.StatusOK {
			return fmt.Errorf("%s returned %s", p, res.Status)
		}
		var pretty map[string]any
		if json.Unmarshal(body, &pretty) == nil {
			out, _ := json.MarshalIndent(pretty, "", "  ")
			fmt.Printf("%s\n%s\n", p, out)
		}
	}
	return nil
}

func privPing(socket string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var res priv.PingResult
	if err := priv.NewClient(socket).Call(ctx, priv.OpPing, nil, &res); err != nil {
		return err
	}
	fmt.Printf("hardyd-priv %s on %s (euid %d) at %s\n", res.Version, res.Hostname, res.EUID, res.Time.Format(time.RFC3339))
	return nil
}

// recovery resets a password or creates an admin by writing the database
// directly. It's the break-glass path for when nobody can sign in.
func recovery(dbPath string, args []string, fromStdin, createAdmin bool) error {
	if len(args) != 1 {
		return errors.New("expected exactly one username")
	}
	name := args[0]
	pw, err := readNewPassword(fromStdin)
	if err != nil {
		return err
	}
	ctx := context.Background()
	db, err := store.Open(ctx, dbPath)
	if err != nil {
		return fmt.Errorf("open %s (run as root?): %w", dbPath, err)
	}
	defer db.Close()
	users := &auth.Users{DB: db}
	sessions := &auth.Sessions{DB: db}
	log := &audit.Log{DB: db}
	actor := "hardyctl@" + hostname()

	if createAdmin {
		u, err := users.Create(ctx, auth.NewUser{Username: name, Password: pw, Role: auth.RoleAdmin, BreakGlass: true})
		if err != nil {
			return err
		}
		_ = log.Record(ctx, audit.Entry{Actor: actor, Action: "recovery.create_admin", Target: u.Username, Outcome: audit.Success})
		fmt.Printf("Created administrator %q.\n", u.Username)
		return nil
	}

	u, err := users.GetByName(ctx, name)
	if err != nil {
		return fmt.Errorf("user %q: %w", name, err)
	}
	if err := users.SetPassword(ctx, u.ID, pw); err != nil {
		return err
	}
	no := false
	if _, err := users.Update(ctx, u.ID, auth.UserUpdate{Disabled: &no}); err != nil {
		return err
	}
	_ = sessions.RevokeUser(ctx, u.ID)
	_ = log.Record(ctx, audit.Entry{Actor: actor, Action: "recovery.reset_password", Target: u.Username, Outcome: audit.Success})
	fmt.Printf("Password for %q reset; the account is enabled and its sessions were signed out.\n", u.Username)
	return nil
}

func readNewPassword(fromStdin bool) (string, error) {
	if fromStdin || !term.IsTerminal(int(os.Stdin.Fd())) {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return "", fmt.Errorf("read password: %w", err)
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
	fmt.Fprint(os.Stderr, "New password: ")
	a, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	fmt.Fprint(os.Stderr, "Repeat password: ")
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if string(a) != string(b) {
		return "", errors.New("passwords don't match")
	}
	return string(a), nil
}

func hostname() string {
	h, _ := os.Hostname()
	return h
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func bootList() error {
	cfg, err := boot.LoadConfig(boot.ConfigPath)
	if err != nil {
		return err
	}
	bes, err := boot.List(context.Background(), boot.Env{Runner: sysexec.Exec{}, Root: "/"}, cfg.Pool)
	if err != nil {
		return err
	}
	for _, be := range bes {
		mark := " "
		if be.Default {
			mark = "*"
		}
		fmt.Printf("%s %-40s %-20s %s\n", mark, be.Name, be.Version, time.Unix(be.Created, 0).Format("2006-01-02 15:04"))
	}
	return nil
}

func bootSync(args []string) error {
	if os.Geteuid() != 0 {
		return errors.New("boot-sync must run as root")
	}
	cfg, err := boot.LoadConfig(boot.ConfigPath)
	if errors.Is(err, boot.ErrNoConfig) {
		// The live ISO, an image build, or a package on plain Debian.
		fmt.Println("hardyctl boot-sync: not a HardyOS install; nothing to do")
		return nil
	}
	if err != nil {
		return err
	}
	opts := boot.SyncOptions{}
	for _, a := range args {
		switch a {
		case "--reinstall":
			opts.InstallGRUB = true
		default:
			return fmt.Errorf("unknown option %q", a)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	entries, err := boot.Sync(ctx, boot.Env{Runner: sysexec.Exec{}, Root: "/"}, cfg, opts)
	for i, e := range entries {
		def := ""
		if i == 0 {
			def = " (default)"
		}
		fmt.Printf("boot entry: %s%s\n", e.Title, def)
	}
	return err
}
