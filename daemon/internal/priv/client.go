package priv

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"
)

// Client calls hardyd-priv operations.
type Client struct {
	Socket string
}

// NewClient returns a client for the socket at path (DefaultSocket if empty).
func NewClient(path string) *Client {
	if path == "" {
		path = DefaultSocket
	}
	return &Client{Socket: path}
}

// Call runs op with args and decodes the result into out (which may be nil).
func (c *Client) Call(ctx context.Context, op string, args any, out any) error {
	var raw json.RawMessage
	if args != nil {
		b, err := json.Marshal(args)
		if err != nil {
			return fmt.Errorf("encode args: %w", err)
		}
		raw = b
	}

	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", c.Socket)
	if err != nil {
		return &Error{Code: CodeUnavailable, Message: err.Error()}
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(15 * time.Minute))
	}

	// The helper may answer and close before reading everything (it rejects
	// unauthorized callers immediately), so a failed write isn't final:
	// read the reply first and only report the write error if there is none.
	writeErr := json.NewEncoder(conn).Encode(Request{Op: op, Args: raw})
	var res Response
	if err := json.NewDecoder(io.LimitReader(conn, 64<<20)).Decode(&res); err != nil {
		if writeErr != nil {
			return fmt.Errorf("send request: %w", writeErr)
		}
		return fmt.Errorf("read response: %w", err)
	}
	if !res.OK {
		if res.Error != nil {
			return res.Error
		}
		return Errorf(CodeFailed, "operation failed without an error")
	}
	if out != nil && len(res.Data) > 0 {
		if err := json.Unmarshal(res.Data, out); err != nil {
			return fmt.Errorf("decode result: %w", err)
		}
	}
	return nil
}
