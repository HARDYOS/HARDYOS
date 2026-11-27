//go:build !linux

package sftpauth

import (
	"errors"
	"net"
)

// PeerUID is only known on Linux: elsewhere nobody is root to hardyd.
func PeerUID(net.Conn) (uint32, error) {
	return 0, errors.New("peer credentials aren't available on this system")
}
