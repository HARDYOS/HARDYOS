// Command hardyrelease creates the release signing key and signed update
// bundles. It runs on the computer that builds releases, never on servers.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/hardyos/hardyos/daemon/internal/update"
)

const usage = `hardyrelease: sign HardyOS releases

  hardyrelease keygen [-key FILE] [-pub FILE] [-comment TEXT]
      Create the release signing key (once). The private key stays on this
      computer; commit the public key so servers trust your updates.

  hardyrelease bundle -version V -rootfs FILE -out FILE [-key FILE] [-arch amd64] [-notes TEXT]
      Sign a system image (the ISO build's filesystem.squashfs) into an
      update file (.hupd).

  hardyrelease verify [-pub FILE] FILE
      Check an update file's signature (against -pub, or the keys built into
      this program).
`

func defaultKey() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = filepath.Join(os.Getenv("HOME"), ".config")
	}
	return filepath.Join(dir, "hardyos", "release.key")
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = keygen(os.Args[2:])
	case "bundle":
		err = bundle(os.Args[2:])
	case "verify":
		err = verify(os.Args[2:])
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	keyPath := fs.String("key", defaultKey(), "where to write the private key")
	pubPath := fs.String("pub", "daemon/internal/update/keys/release.pub", "where to write the public key")
	comment := fs.String("comment", "hardyos-release", "comment stored with the public key")
	_ = fs.Parse(args)
	if _, err := os.Stat(*keyPath); err == nil {
		return fmt.Errorf("%s already exists; refusing to replace a release key (servers trust the old one)", *keyPath)
	}
	priv, pub, err := update.GenerateKey(*comment)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(*keyPath), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(*keyPath, []byte(priv), 0o600); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(*pubPath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(*pubPath, []byte(pub), 0o644); err != nil {
		return err
	}
	fmt.Printf("Private key: %s (back it up somewhere safe; never commit it)\n", *keyPath)
	fmt.Printf("Public key:  %s (commit this file)\n", *pubPath)
	return nil
}

func bundle(args []string) error {
	fs := flag.NewFlagSet("bundle", flag.ExitOnError)
	keyPath := fs.String("key", defaultKey(), "private key")
	version := fs.String("version", "", "HardyOS version in the image")
	rootfs := fs.String("rootfs", "", "system image (filesystem.squashfs)")
	out := fs.String("out", "", "update file to write (.hupd)")
	arch := fs.String("arch", "amd64", "CPU architecture of the image")
	notes := fs.String("notes", "", "release notes shown before installing")
	_ = fs.Parse(args)
	if *version == "" || *rootfs == "" || *out == "" {
		return errors.New("-version, -rootfs and -out are required")
	}
	kb, err := os.ReadFile(*keyPath)
	if err != nil {
		return fmt.Errorf("read the release key: %w (create it with `make release-key`)", err)
	}
	priv, err := update.ParsePrivateKey(kb)
	if err != nil {
		return err
	}
	tmp := *out + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	m, err := update.CreateBundle(f, priv, *version, *arch, *notes, *rootfs)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, *out); err != nil {
		return err
	}
	fmt.Printf("Signed HardyOS %s (%s, %d MB) -> %s\n", m.Version, m.Arch, m.RootFS.Size>>20, *out)
	return nil
}

func verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	pubPath := fs.String("pub", "", "public key to check against (default: built-in keys)")
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("give one update file")
	}
	keys := update.TrustedKeys("")
	if *pubPath != "" {
		b, err := os.ReadFile(*pubPath)
		if err != nil {
			return err
		}
		k, err := update.ParsePublicKey(string(b))
		if err != nil {
			return err
		}
		keys = []update.PublicKey{k}
	}
	m, err := update.ReadManifest(fs.Arg(0), keys)
	if err != nil {
		return err
	}
	fmt.Printf("OK: HardyOS %s for %s, signed by a trusted key; image %d MB, sha256 %s\n", m.Version, m.Arch, m.RootFS.Size>>20, m.RootFS.SHA256)
	return nil
}
