package main

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/hardyos/hardyos/daemon/internal/nbstandby"
	"github.com/hardyos/hardyos/daemon/internal/zfs"
)

// standbyCmd shows the NetBird standby's key fingerprints from root's own
// state, so the administrator can compare them with the VPS (decision 421):
// what the browser shows comes through hardyd, this doesn't.
func standbyCmd(args []string) error {
	if len(args) != 1 || args[0] != "fingerprint" {
		return errors.New("usage: hardyctl netbird-standby fingerprint")
	}
	st, err := (&nbstandby.Root{Dir: filepath.Join(zfs.KeyDir, "netbird-standby")}).Status(context.Background())
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
	return nil
}
