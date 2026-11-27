//go:build !linux

package vms

import (
	"context"
	"errors"
)

// watchNetlink6 needs Linux's netlink: elsewhere the periodic refresh
// alone follows the networks.
func watchNetlink6(context.Context, func()) error {
	return errors.New("netlink isn't available on this system")
}
