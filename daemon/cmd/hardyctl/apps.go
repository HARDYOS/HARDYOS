package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hardyos/hardyos/daemon/internal/apps"
)

// appPack builds a .hardyapp from a folder holding hardyapp.json,
// compose.yaml and the icon.
func appPack(args []string) error {
	fs := flag.NewFlagSet("app-pack", flag.ContinueOnError)
	out := fs.String("o", "", "output file (default: <id>.hardyapp in the current folder)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: hardyctl app-pack [-o file.hardyapp] <folder>")
	}
	b, err := apps.Pack(fs.Arg(0))
	if err != nil {
		return describe(err)
	}
	p, err := apps.ReadPackage(b)
	if err != nil {
		return describe(err)
	}
	if *out == "" {
		*out = p.Manifest.ID + ".hardyapp"
	}
	if err := os.WriteFile(*out, b, 0o644); err != nil {
		return err
	}
	fmt.Printf("%s %s -> %s (%d KB, sha256 %s)\n", p.Manifest.Name, p.Manifest.Version, filepath.Clean(*out), (len(b)+1023)>>10, p.SHA256)
	return nil
}

// appCheck checks a .hardyapp file or a package folder, and lists what the
// install dialog will show.
func appCheck(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: hardyctl app-check <file.hardyapp | folder>")
	}
	var b []byte
	var err error
	if fi, statErr := os.Stat(args[0]); statErr == nil && fi.IsDir() {
		b, err = apps.Pack(args[0])
	} else {
		b, err = os.ReadFile(args[0])
	}
	if err != nil {
		return describe(err)
	}
	p, err := apps.ReadPackage(b)
	if err != nil {
		return describe(err)
	}
	m := p.Manifest
	fmt.Printf("%s %s (%s) by %s: OK\n", m.Name, m.Version, m.ID, m.Publisher)
	for _, pt := range m.Ports {
		fmt.Printf("  port %-10s %5d  %s\n", pt.Name, pt.Default, pt.Label)
	}
	for _, s := range m.Settings {
		if s.Hidden() {
			fmt.Printf("  setting %s: generated password\n", s.Env)
		} else {
			fmt.Printf("  setting %s: %s\n", s.Env, s.Label)
		}
	}
	for _, d := range apps.DescribePermissions(m) {
		fmt.Printf("  permission: %s\n", d)
	}
	fmt.Println("The compose file is checked against HardyOS's rules when the app is installed (docker compose config).")
	return nil
}

func describe(err error) error {
	var p apps.Problems
	if errors.As(err, &p) && len(p) > 1 {
		return errors.New("the package has problems:\n  - " + strings.Join(p, "\n  - "))
	}
	return err
}
