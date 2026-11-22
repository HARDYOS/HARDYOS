package vms

import (
	"os/exec"
	"strings"
)

func shellJoin(args []string) string {
	q := make([]string, len(args))
	for i, a := range args {
		q[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
	}
	return strings.Join(q, " ")
}

func runUnshare(script string) (string, error) {
	out, err := exec.Command("unshare", "-n", "--", "sh", "-c", script).CombinedOutput()
	return string(out), err
}
