//go:build !linux

package priv

import (
	"errors"
	"net"
)

// peerUID is only implemented on Linux; elsewhere every caller is rejected.
func peerUID(conn *net.UnixConn) (uint32, error) {
	return ^uint32(0), errors.New("peer credentials not supported on this OS")
}
