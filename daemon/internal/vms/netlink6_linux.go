//go:build linux

package vms

import (
	"context"
	"errors"

	"golang.org/x/sys/unix"
)

// watchNetlink6 calls kick for every IPv6 address, route or link change
// the kernel reports, until ctx ends.
func watchNetlink6(ctx context.Context, kick func()) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	groups := uint32(unix.RTMGRP_IPV6_IFADDR | unix.RTMGRP_IPV6_ROUTE | unix.RTMGRP_LINK)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: groups}); err != nil {
		return err
	}
	// Wake up every second to notice ctx.
	tv := unix.Timeval{Sec: 1}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return err
	}
	buf := make([]byte, 64<<10)
	for ctx.Err() == nil {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		switch {
		case err == nil && n > 0:
			kick()
		case errors.Is(err, unix.EAGAIN), errors.Is(err, unix.EINTR):
		case errors.Is(err, unix.ENOBUFS):
			kick() // events were lost: refresh anyway
		case err != nil:
			return err
		}
	}
	return nil
}
