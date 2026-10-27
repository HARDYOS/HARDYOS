// Package sysexec runs system commands (zpool, zfs, lsblk, smartctl) behind
// an interface, so privileged operations can be unit-tested with a fake.
package sysexec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
)

// Result is the outcome of one command.
type Result struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

// Runner runs a command. Implementations never use a shell: name and args go
// straight to execve, so arguments can't be interpreted as shell syntax.
type Runner interface {
	// Run executes name with args. stdin may be nil. A non-zero exit is
	// reported through Result.ExitCode with a nil error; err is reserved for
	// failures to start the command or context cancellation.
	Run(ctx context.Context, stdin []byte, name string, args ...string) (Result, error)
}

// Exec is the real Runner.
type Exec struct{}

// Run implements Runner.
func (Exec) Run(ctx context.Context, stdin []byte, name string, args ...string) (Result, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	own(cmd)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	err := ignoreWaitDelay(cmd.Run())
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

// OwnGroup is for commands started elsewhere without a context (long-running
// zfs send and receive): their own process group and a bounded wait for
// their pipes, like Exec's. There is no cmd.Cancel (exec refuses one on a
// command not made with CommandContext); the caller kills the group itself
// (KillGroup).
func OwnGroup(cmd *exec.Cmd) {
	ownGroup(cmd)
	cmd.WaitDelay = WaitDelay
}

// ignoreWaitDelay drops exec.ErrWaitDelay: the command itself finished
// successfully (Wait reports that error only then), but a process it left
// running (a daemon a package started) still held its output open.
func ignoreWaitDelay(err error) error {
	if errors.Is(err, exec.ErrWaitDelay) {
		return nil
	}
	return err
}

// Output runs a command and returns stdout, turning a non-zero exit into an
// error that includes the command's stderr.
func Output(ctx context.Context, r Runner, name string, args ...string) ([]byte, error) {
	res, err := r.Run(ctx, nil, name, args...)
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		return res.Stdout, &CommandError{Name: name, Args: args, Result: res}
	}
	return res.Stdout, nil
}

// CommandError describes a command that exited non-zero.
type CommandError struct {
	Name   string
	Args   []string
	Result Result
}

func (e *CommandError) Error() string {
	msg := strings.TrimSpace(string(e.Result.Stderr))
	if msg == "" {
		msg = strings.TrimSpace(string(e.Result.Stdout))
	}
	if len(msg) > 500 {
		msg = msg[:500] + "…"
	}
	return fmt.Sprintf("%s exited %d: %s", e.Name, e.Result.ExitCode, msg)
}

// Fake is a scriptable Runner for tests. Responses are matched on the full
// command line ("zpool list -Hp ..."); unmatched commands fail the call.
type Fake struct {
	mu        sync.Mutex
	responses map[string]Result
	prefixes  []prefixResp
	Calls     []Call
}

type prefixResp struct {
	prefix string
	res    Result
}

// Call records one invocation of the fake.
type Call struct {
	Line  string
	Stdin []byte
	// Env holds the extra environment variables of a RunEnv call.
	Env []string
}

// On sets the result for an exact command line.
func (f *Fake) On(line string, stdout string) *Fake {
	return f.OnResult(line, Result{Stdout: []byte(stdout)})
}

// OnResult sets a full result for an exact command line.
func (f *Fake) OnResult(line string, r Result) *Fake {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.responses == nil {
		f.responses = map[string]Result{}
	}
	f.responses[line] = r
	return f
}

// OnPrefix sets the result for any command line starting with prefix.
func (f *Fake) OnPrefix(prefix string, r Result) *Fake {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.prefixes = append(f.prefixes, prefixResp{prefix, r})
	return f
}

// Run implements Runner.
func (f *Fake) Run(ctx context.Context, stdin []byte, name string, args ...string) (Result, error) {
	line := strings.Join(append([]string{name}, args...), " ")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Calls = append(f.Calls, Call{Line: line, Stdin: stdin})
	if r, ok := f.responses[line]; ok {
		return r, nil
	}
	for _, p := range f.prefixes {
		if strings.HasPrefix(line, p.prefix) {
			return p.res, nil
		}
	}
	return Result{ExitCode: 127, Stderr: []byte("fake: unexpected command: " + line)}, nil
}

// Lines returns the command lines run so far.
func (f *Fake) Lines() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.Calls))
	for i, c := range f.Calls {
		out[i] = c.Line
	}
	return out
}
