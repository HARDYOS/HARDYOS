package sysexec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// EnvRunner runs a command with extra environment variables (on top of
// Exec's fixed PATH and LC_ALL). Samba's tools take a password's file
// descriptor from PASSWD_FD, so the password itself can go on stdin and
// never on a command line.
type EnvRunner interface {
	RunEnv(ctx context.Context, env []string, stdin []byte, name string, args ...string) (Result, error)
}

// RunEnv runs a command with extra environment variables through r, which
// must implement EnvRunner.
func RunEnv(ctx context.Context, r Runner, env []string, stdin []byte, name string, args ...string) (Result, error) {
	er, ok := r.(EnvRunner)
	if !ok {
		return Result{}, fmt.Errorf("%T can't pass environment variables", r)
	}
	for _, e := range env {
		k, _, ok := strings.Cut(e, "=")
		if !ok || k == "" || k == "PATH" || strings.HasPrefix(k, "LD_") {
			return Result{}, fmt.Errorf("refusing environment variable %q", k)
		}
	}
	return er.RunEnv(ctx, env, stdin, name, args...)
}

// OutputEnv is Output with extra environment variables.
func OutputEnv(ctx context.Context, r Runner, env []string, stdin []byte, name string, args ...string) ([]byte, error) {
	res, err := RunEnv(ctx, r, env, stdin, name, args...)
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		return res.Stdout, &CommandError{Name: name, Args: args, Result: res}
	}
	return res.Stdout, nil
}

// RunEnv implements EnvRunner.
func (Exec) RunEnv(ctx context.Context, env []string, stdin []byte, name string, args ...string) (Result, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append([]string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}, env...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	err := cmd.Run()
	res := Result{Stdout: out.Bytes(), Stderr: errb.Bytes()}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		res.ExitCode = exitErr.ExitCode()
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		return res, nil
	}
	return res, err
}

// RunEnv implements EnvRunner; the environment is recorded in Calls.
func (f *Fake) RunEnv(ctx context.Context, env []string, stdin []byte, name string, args ...string) (Result, error) {
	res, err := f.Run(ctx, stdin, name, args...)
	f.mu.Lock()
	f.Calls[len(f.Calls)-1].Env = append([]string(nil), env...)
	f.mu.Unlock()
	return res, err
}
