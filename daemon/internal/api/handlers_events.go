package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/coder/websocket"

	"github.com/hardyos/hardyos/daemon/internal/auth"
)

// handleEvents upgrades to a WebSocket and streams events the user may see.
// The server only writes; client messages are read and discarded so pings
// and closes are processed.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request, u *auth.User) {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// Same-origin only: the library rejects cross-origin upgrades by default.
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return // Accept already wrote an HTTP error
	}
	defer conn.CloseNow()

	sub := s.cfg.Events.Subscribe(u.ID, u.IsAdmin(), 256)
	defer s.cfg.Events.Unsubscribe(sub)

	ctx := conn.CloseRead(r.Context())
	ping := time.NewTicker(30 * time.Second)
	defer ping.Stop()

	if err := writeWS(ctx, conn, map[string]any{"type": "hello", "user": u.Username}); err != nil {
		return
	}
	for {
		select {
		case <-ctx.Done():
			conn.Close(websocket.StatusNormalClosure, "")
			return
		case e, ok := <-sub.C:
			if !ok {
				return
			}
			if err := writeWS(ctx, conn, e); err != nil {
				return
			}
		case <-ping.C:
			pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := conn.Ping(pctx)
			cancel()
			if err != nil {
				return
			}
		}
	}
}

func writeWS(ctx context.Context, conn *websocket.Conn, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return conn.Write(wctx, websocket.MessageText, b)
}
