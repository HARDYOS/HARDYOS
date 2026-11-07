package cluster

import (
	"errors"
	"regexp"
)

// bootIDRE is what a boot id may look like: the kernel's
// /proc/sys/kernel/random/boot_id is a UUID; tests use short names.
var bootIDRE = regexp.MustCompile(`^[0-9a-zA-Z-]{1,64}$`)

// ValidBootID checks a boot id. It is the one format every part uses:
// member.update and node.rejoin record it in the log (part C), and the
// storage node's root verifies it in the node's signed rejoin statement
// (part B), so an id the log accepts can always be signed and verified.
func ValidBootID(id string) error {
	if !bootIDRE.MatchString(id) {
		return errors.New("boot id isn't valid (letters, digits and dashes, at most 64)")
	}
	return nil
}
