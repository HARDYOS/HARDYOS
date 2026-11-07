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

// ALPNStream is the only StreamDialer: the peer API's streamed fallback
// is gone because the peer API may run over NetBird, and a live
// migration's connection never does (decision 332). It dials the
// cluster port's hardyos-migrate/1
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
