//go:build !linux

package shares

import (
	"context"
	"errors"
)

var errNoACL = errors.New("POSIX ACLs are only supported on Linux")

// SetPeopleRoot needs Linux.
func SetPeopleRoot(string, PeopleACL) (bool, error) { return false, errNoACL }

// PeopleRootMatches needs Linux.
func PeopleRootMatches(string, PeopleACL) (bool, error) { return false, errNoACL }

// ApplyPeopleTree needs Linux.
func ApplyPeopleTree(context.Context, string, PeopleACL) (PeopleStats, error) {
	return PeopleStats{}, errNoACL
}
