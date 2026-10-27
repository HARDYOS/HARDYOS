package replica

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"
)

// The real starter runs commands without a context (exec refuses a Cancel
// then) in their own process group, and Kill ends them.
func TestExecStarter(t *testing.T) {
	var out bytes.Buffer
	p, err := ExecStarter{}.Start("cat", nil, strings.NewReader("hello"), &out, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Wait(); err != nil || out.String() != "hello" {
		t.Fatalf("%v %q", err, out.String())
	}
	p, err = ExecStarter{}.Start("sleep", []string{"30"}, nil, io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	p.Kill()
	_ = p.Wait()
	if time.Since(start) > 5*time.Second {
		t.Fatal("Kill didn't end the command")
	}
}
