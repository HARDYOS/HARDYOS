package priv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"
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

// CallFile runs an operation that hands over an open file with its result
// (like terminal.open). The caller owns the returned file.
func (c *Client) CallFile(ctx context.Context, op string, args any, out any) (*os.File, error) {
	raw, err := json.Marshal(args)
	if err != nil {
		return nil, fmt.Errorf("encode args: %w", err)
	}
	var d net.Dialer
	nc, err := d.DialContext(ctx, "unix", c.Socket)
	if err != nil {
		return nil, &Error{Code: CodeUnavailable, Message: err.Error()}
	}
	conn := nc.(*net.UnixConn)
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(time.Minute))
	}
	if err := json.NewEncoder(conn).Encode(Request{Op: op, Args: raw}); err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}
	var body []byte
	var file *os.File
	buf := make([]byte, 64<<10)
	oob := make([]byte, unix.CmsgSpace(4))
	for !bytes.Contains(body, []byte("\n")) {
		n, oobn, _, _, err := conn.ReadMsgUnix(buf, oob)
		if oobn > 0 && file == nil {
			if msgs, perr := unix.ParseSocketControlMessage(oob[:oobn]); perr == nil {
				for _, m := range msgs {
					if fds, ferr := unix.ParseUnixRights(&m); ferr == nil && len(fds) > 0 {
						file = os.NewFile(uintptr(fds[0]), op)
						for _, extra := range fds[1:] {
							_ = unix.Close(extra)
						}
					}
				}
			}
		}
		body = append(body, buf[:n]...)
		if err != nil {
			if len(body) > 0 && bytes.Contains(body, []byte("\n")) {
				break
			}
			if file != nil {
				file.Close()
			}
			return nil, fmt.Errorf("read response: %w", err)
		}
		if len(body) > 64<<20 {
			break
		}
	}
	var res Response
	if err := json.Unmarshal(bytes.TrimSpace(body), &res); err != nil {
		if file != nil {
			file.Close()
		}
		return nil, fmt.Errorf("read response: %w", err)
	}
	if !res.OK {
		if file != nil {
			file.Close()
		}
		if res.Error != nil {
			return nil, res.Error
		}
		return nil, Errorf(CodeFailed, "operation failed without an error")
	}
	if file == nil {
		return nil, Errorf(CodeFailed, "%s didn't hand over a file", op)
	}
	if out != nil && len(res.Data) > 0 {
		if err := json.Unmarshal(res.Data, out); err != nil {
			file.Close()
			return nil, fmt.Errorf("decode result: %w", err)
		}
	}
	return file, nil
}
