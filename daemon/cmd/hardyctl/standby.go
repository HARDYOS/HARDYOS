package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hardyos/hardyos/daemon/internal/nbstandby"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/zfs"
)

const standbyUsage = `usage: hardyctl netbird-standby <command>
  fingerprint            show the keys, the name and the addresses from root's state
  address <ipv4> [ipv6]  set this server's public addresses (then: rebind)
  rebind                 allow the current addresses and VPS for the adopted name
  dns-preview <name>     list the Cloudflare records at name
  adopt <name> <id>...   let HardyOS manage exactly these records at name
  forget-dns             stop HardyOS managing the adopted name`

// standbyCmd runs the NetBird standby's console commands. They read and
// write root's own state, not through hardyd, so they work when hardyd is
// suspected (decisions 421 and 424): the person at the console stands in
// for the Cloudflare token pasted again.
func standbyCmd(args []string) error {
	if len(args) == 0 {
		return errors.New(standbyUsage)
	}
	dir := filepath.Join(zfs.KeyDir, "netbird-standby")
	if args[0] != "fingerprint" && os.Geteuid() != 0 {
		return errors.New("run this as root on the server's console")
	}
	ctx := context.Background()
	env := priv.ConsoleEnv(zfs.KeyDir, dir)
	switch args[0] {
	case "fingerprint":
		if len(args) != 1 {
			return errors.New(standbyUsage)
		}
		return standbyFingerprint(dir)
	case "address":
		if len(args) < 2 || len(args) > 3 {
			return errors.New(standbyUsage)
		}
		v6 := ""
		if len(args) == 3 {
			v6 = args[2]
		}
		st, err := nbstandby.SetAddressConsole(dir, args[1], v6)
		if err != nil {
			return err
		}
		fmt.Printf("DNS may point %s at %s %s\n", st.Hostname, st.PublicIPv4, st.PublicIPv6)
		if priv.StandbyDNSName(zfs.KeyDir) != "" {
			fmt.Println("Run `hardyctl netbird-standby rebind` (or confirm with the Cloudflare token in Control Panel) to allow it.")
		}
		return nil
	case "rebind":
		if len(args) != 1 {
			return errors.New(standbyUsage)
		}
		b, ok := nbstandby.CurrentBinding(dir)
		if !ok {
			return errors.New("the NetBird standby isn't set up")
		}
		printBinding(b)
		if err := confirmName(b.Host); err != nil {
			return err
		}
		if err := priv.ConsoleRebind(env); err != nil {
			return err
		}
		fmt.Println("Allowed.")
		return nil
	case "dns-preview":
		if len(args) != 2 {
			return errors.New(standbyUsage)
		}
		pv, err := priv.ConsolePreview(ctx, env, args[1])
		if err != nil {
			return err
		}
		for _, r := range pv.Records {
			fmt.Printf("%s  %-5s %s\n", r.ID, r.Type, r.Content)
		}
		if !pv.Adoptable {
			fmt.Println("Can't be adopted:", pv.Problem)
		}
		return nil
	case "adopt":
		if len(args) < 3 {
			return errors.New(standbyUsage)
		}
		b, ok := nbstandby.CurrentBinding(dir)
		if !ok {
			return errors.New("the NetBird standby isn't set up")
		}
		printBinding(b)
		if err := confirmName(args[1]); err != nil {
			return err
		}
		if err := priv.ConsoleAdopt(ctx, env, args[1], args[2:]); err != nil {
			return err
		}
		fmt.Println("Adopted.")
		return nil
	case "forget-dns":
		if len(args) != 1 {
			return errors.New(standbyUsage)
		}
		name := priv.StandbyDNSName(zfs.KeyDir)
		if name == "" {
			return errors.New("HardyOS doesn't manage a standby name")
		}
		if err := confirmName(name); err != nil {
			return err
		}
		return priv.ConsoleForget(env)
	}
	return errors.New(standbyUsage)
}

func standbyFingerprint(dir string) error {
	st, err := (&nbstandby.Root{Dir: dir}).Status(context.Background())
	if err != nil {
		return err
	}
	if st.PublicKey == "" {
		return errors.New("the NetBird standby isn't set up")
	}
	fmt.Printf("HardyOS's key:     %s\n", nbstandby.KeyFingerprint(st.PublicKey))
	if st.HostKeyFP != "" {
		fmt.Printf("VPS host key:      %s (%s)\n", st.HostKeyFP, st.VPSHost)
	}
	fmt.Printf("NetBird name:      %s\n", st.Hostname)
	if st.PublicIPv4 != "" || st.PublicIPv6 != "" {
		fmt.Printf("DNS may point at:  %s %s\n", st.PublicIPv4, st.PublicIPv6)
	}
	if b, ok := priv.StandbyDNSBound(zfs.KeyDir); ok {
		cur, _ := nbstandby.CurrentBinding(dir)
		if b == cur {
			fmt.Println("Cloudflare name:   allowed for these values")
		} else {
			fmt.Printf("Cloudflare name:   allowed for %s %s via %s:%d (%s): run rebind to allow the current values\n",
				b.IPv4, b.IPv6, b.VPSHost, b.VPSPort, b.HostKeyFP)
		}
	}
	return nil
}

func printBinding(b nbstandby.Binding) {
	fmt.Printf("NetBird name:      %s\n", b.Host)
	fmt.Printf("DNS may point at:  %s %s\n", b.IPv4, b.IPv6)
	fmt.Printf("VPS:               %s port %d\n", b.VPSHost, b.VPSPort)
	fmt.Printf("VPS host key:      %s\n", b.HostKeyFP)
}

// confirmName asks for the name typed on the console.
func confirmName(name string) error {
	fmt.Printf("Type %s to confirm: ", name)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	if !strings.EqualFold(strings.TrimSuffix(strings.TrimSpace(line), "."), name) {
		return errors.New("not confirmed")
	}
	return nil
}
