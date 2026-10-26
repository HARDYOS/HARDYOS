//go:build !linux

package sftp

import "errors"

// SysMounter is the real Mounter (Linux only).
type SysMounter struct{ NoNewAPI bool }

var errNoMounts = errors.New("bind mounts need Linux")

func (SysMounter) List(string) ([]MountPoint, error)       { return nil, nil }
func (SysMounter) IsMount(string) (bool, error)            { return false, nil }
func (SysMounter) MakePrivate(string) error                { return errNoMounts }
func (SysMounter) Bind(string, uint64, string, bool) error { return errNoMounts }
func (SysMounter) Unmount(string) error                    { return nil }
