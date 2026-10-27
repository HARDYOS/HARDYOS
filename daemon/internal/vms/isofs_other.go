//go:build !linux

package vms

import (
	"errors"
	"os"
)

var errNotLinux = errors.New("virtual machines are only supported on Linux")

func listFolder(*Folder) ([]LibraryFile, error)    { return nil, errNotLinux }
func openFile(*Folder, string) (*os.File, error)   { return nil, errNotLinux }
func grantQEMU(*Folder, string, uint32) error      { return errNotLinux }
func createTemp(*Folder, string) (*os.File, error) { return nil, errNotLinux }
func renameInto(*Folder, string, string) error     { return errNotLinux }
func removeFile(*Folder, string) error             { return errNotLinux }

func chownLike(string, os.FileInfo) {}
