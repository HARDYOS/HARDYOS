package mail

import (
	"context"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"testing"
)

// Decision 319: hardyd only talks to a socket the radicale user owns in a
// folder nobody else can write to.
func TestRadicaleDialerChecksTheSocket(t *testing.T) {
	me, _ := user.Current()
	dir := filepath.Join(t.TempDir(), "radicale")
	_ = os.Mkdir(dir, 0o750)
	sock := filepath.Join(dir, "radicale.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	ctx := context.Background()
	if c, err := (RadicaleDialer{Socket: sock, Owner: me.Username}).DialContext(ctx, "", ""); err != nil {
		t.Fatalf("Radicale's own socket refused: %v", err)
	} else {
		c.Close()
	}
	other := "nobody"
	if me.Username == "nobody" {
		other = "root"
	}
	if _, err := (RadicaleDialer{Socket: sock, Owner: other}).DialContext(ctx, "", ""); err == nil {
		t.Fatal("a socket someone else made was used")
	}
	_ = os.Chmod(dir, 0o777)
	if _, err := (RadicaleDialer{Socket: sock, Owner: me.Username}).DialContext(ctx, "", ""); err == nil {
		t.Fatal("a socket in a folder anyone can write to was used")
	}
}
