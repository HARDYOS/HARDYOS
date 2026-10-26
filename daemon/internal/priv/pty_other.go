//go:build !linux

package priv

import (
	"errors"
	"os"
)

func openPTY(cols, rows int) (master, slave *os.File, err error) {
	return nil, nil, errors.New("terminals need Linux")
}

func setSize(f *os.File, cols, rows int) error { return errors.New("terminals need Linux") }
