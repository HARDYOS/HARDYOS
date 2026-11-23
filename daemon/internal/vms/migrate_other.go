//go:build !linux

package vms

import (
	"context"
	"errors"
	"os"
)

// MigrateConnectArg is hardyd-priv's migration helper subcommand.
const MigrateConnectArg = "migrate-connect"

func connectAs(context.Context, string) (*os.File, error) {
	return nil, errors.New("live migration needs Linux")
}

// MigrateConnectMain is the helper (Linux only).
func MigrateConnectMain([]string) int { return 2 }

func killProcess(int) error { return errors.New("killing a process needs Linux") }

func runAsMigrate(context.Context, string, ...string) ([]byte, error) {
	return nil, errors.New("live migration needs Linux")
}
