package vms

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
)

// Streamer runs the long commands of imports: with a file handed over as
// descriptor 3, with progress, or as a filter. Tests replace it.
type Streamer interface {
	// RunWithFile runs a command with f as descriptor 3 and returns its
	// output.
	RunWithFile(ctx context.Context, f *os.File, name string, args ...string) ([]byte, error)
	// Progress runs a command with f as descriptor 3, reporting the
	// percentages it prints (qemu-img -p).
	Progress(ctx context.Context, f *os.File, onPct func(float64), name string, args ...string) error
	// Pipe runs a filter from in to out, reporting bytes read.
	Pipe(ctx context.Context, in io.Reader, out io.Writer, onRead func(int64), name string, args ...string) error
}

func (m *Manager) stream() Streamer {
	if m.Stream != nil {
		return m.Stream
	}
	return execStreamer{}
}

type execStreamer struct{}

func command(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	return cmd
}

func (execStreamer) RunWithFile(ctx context.Context, f *os.File, name string, args ...string) ([]byte, error) {
	cmd := command(ctx, name, args...)
	cmd.ExtraFiles = []*os.File{f}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s: %v: %s", name, err, strings.TrimSpace(errb.String()))
	}
	return out.Bytes(), nil
}

// qemu-img -p prints "    (12.34/100%)" with carriage returns.
var pctRE = regexp.MustCompile(`\((\d+(?:\.\d+)?)/100%\)`)

func splitCR(data []byte, atEOF bool) (int, []byte, error) {
	for i, b := range data {
		if b == '\r' || b == '\n' {
			return i + 1, data[:i], nil
		}
	}
	if atEOF && len(data) > 0 {
		return len(data), data, nil
	}
	return 0, nil, nil
}

func (execStreamer) Progress(ctx context.Context, f *os.File, onPct func(float64), name string, args ...string) error {
	cmd := command(ctx, name, args...)
	cmd.ExtraFiles = []*os.File{f}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	var errb bytes.Buffer
	cmd.Stderr = &errb
	if err := cmd.Start(); err != nil {
		return err
	}
	sc := bufio.NewScanner(stdout)
	sc.Split(splitCR)
	for sc.Scan() {
		if mt := pctRE.FindSubmatch(sc.Bytes()); mt != nil {
			if p, err := strconv.ParseFloat(string(mt[1]), 64); err == nil {
				onPct(p)
			}
		}
	}
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(errb.String()))
	}
	return nil
}

type countingReader struct {
	r  io.Reader
	n  atomic.Int64
	on func(int64)
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 && c.on != nil {
		c.on(c.n.Add(int64(n)))
	}
	return n, err
}

func (execStreamer) Pipe(ctx context.Context, in io.Reader, out io.Writer, onRead func(int64), name string, args ...string) error {
	cmd := command(ctx, name, args...)
	cmd.Stdin = &countingReader{r: in, on: onRead}
	cmd.Stdout = out
	var errb bytes.Buffer
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(errb.String()))
	}
	return nil
}
