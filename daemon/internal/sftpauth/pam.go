package sftpauth

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/hardyos/hardyos/daemon/internal/auth"
)

// PAM runs one op for pam_exec: env is the process environment (pam_exec
// sets PAM_TYPE, PAM_USER and PAM_RHOST) and stdin holds the typed
// password for OpApp (pam_exec's expose_authtok). It returns the exit
// status: 0 for yes, 1 for no or anything unexpected (sshd then denies or
// goes on, as the PAM block says).
func PAM(ctx context.Context, op string, env func(string) string, stdin io.Reader, socket string, log io.Writer) int {
	if env("PAM_TYPE") != "auth" {
		fmt.Fprintln(log, "pam-sftp: only for sshd's auth stack")
		return 1
	}
	req := Request{Op: op, User: env("PAM_USER"), RHost: env("PAM_RHOST")}
	if op == OpApp {
		b, _ := io.ReadAll(io.LimitReader(stdin, 1024))
		b = bytes.TrimRight(b, "\x00\r\n")
		pw := string(b)
		// Only something shaped like an app password ever leaves sshd
		// this way; the account's own password goes to winbind alone.
		if !auth.LooksLikeAppPassword(pw) {
			return 1
		}
		req.Password = pw
	}
	a, err := Ask(ctx, socket, req)
	if err != nil {
		fmt.Fprintln(log, "pam-sftp:", err)
		return 1
	}
	if !a.OK {
		if a.Reason != "" {
			fmt.Fprintln(log, "pam-sftp:", a.Reason)
		}
		return 1
	}
	return 0
}
