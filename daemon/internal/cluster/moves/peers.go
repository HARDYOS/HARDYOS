package moves

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/priv"
)

// PeerStream is a StreamDialer over the peer API: one streamed request
// whose body carries the source's libvirt bytes and whose answer carries
// the destination's (HTTP/2 full duplex on the cluster port).
type PeerStream struct{ Peers cluster.PeerClient }

// DialMigrate implements StreamDialer.
func (p PeerStream) DialMigrate(ctx context.Context, node cluster.NodeID, token string) (io.ReadWriteCloser, error) {
	pr, pw := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://peer"+cluster.PeerPathPrefix+PathStream+"?token="+url.QueryEscape(token), pr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	res, err := p.Peers.Do(ctx, node, req)
	if err != nil {
		pw.Close()
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		res.Body.Close()
		pw.Close()
		return nil, fmt.Errorf("%s refused the migration stream: %s", node, res.Status)
	}
	return &duplex{r: res.Body, w: pw}, nil
}

// ALPNStream is a StreamDialer over the cluster port's hardyos-migrate/1
// (part A's stream layer: LAN, then the storage network, never NetBird):
// the token line, the destination's MigrateOK, then the libvirt bytes.
// The destination serves it with Node.ServeMigrateConn.
type ALPNStream struct {
	Dial func(ctx context.Context, node cluster.NodeID) (net.Conn, error)
}

// DialMigrate implements StreamDialer.
func (a ALPNStream) DialMigrate(ctx context.Context, node cluster.NodeID, token string) (io.ReadWriteCloser, error) {
	conn, err := a.Dial(ctx, node)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(conn, MigrateTokenLine(token)); err != nil {
		conn.Close()
		return nil, err
	}
	br := bufio.NewReaderSize(conn, 512)
	line, err := br.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("%s: the migration connection: %w", node, err)
	}
	if line = strings.TrimSpace(line); line != MigrateOK {
		conn.Close()
		return nil, fmt.Errorf("%s refused the migration connection: %s", node, strings.TrimPrefix(line, "no "))
	}
	_ = conn.SetDeadline(time.Time{})
	return &bufConn{Conn: conn, r: br}, nil
}

type duplex struct {
	r io.ReadCloser
	w *io.PipeWriter
}

func (d *duplex) Read(b []byte) (int, error)  { return d.r.Read(b) }
func (d *duplex) Write(b []byte) (int, error) { return d.w.Write(b) }
func (d *duplex) Close() error {
	d.w.Close()
	return d.r.Close()
}

// PeerImages is runtime.ImageSource over the peer API: the owner lists the
// images its cluster app uses.
type PeerImages struct {
	Peers cluster.PeerClient
	Self  func() cluster.NodeID
	Priv  interface {
		Call(ctx context.Context, op string, args, out any) error
	}
}

// Images implements runtime.ImageSource.
func (p PeerImages) Images(ctx context.Context, owner cluster.NodeID, app string) ([]string, error) {
	var res priv.ImagesResult
	if p.Self != nil && owner == p.Self() && p.Priv != nil {
		err := p.Priv.Call(ctx, priv.OpAppsClusterImages, priv.AppRef{ID: app}, &res)
		return res.Images, err
	}
	err := p.Peers.Call(ctx, owner, http.MethodGet, cluster.PeerPathPrefix+PathImages+"?app="+url.QueryEscape(app), nil, &res)
	return res.Images, err
}
