// Package priv defines the protocol between hardyd (unprivileged) and
// hardyd-priv (root). The helper exposes a fixed allowlist of named
// operations; there is deliberately no generic "run a command" operation.
//
// Wire format: one JSON Request per connection, answered by one JSON
// Response, over a unix socket. Each operation validates its own arguments.
package priv

import (
	"encoding/json"
	"errors"
	"fmt"
)

// DefaultSocket is where hardyd-priv listens on an installed system.
const DefaultSocket = "/run/hardyos/priv.sock"

// MaxRequestBytes bounds a single request so a client cannot exhaust memory.
const MaxRequestBytes = 1 << 20

// Request asks the helper to run one named operation.
type Request struct {
	Op   string          `json:"op"`
	Args json.RawMessage `json:"args,omitempty"`
}

// Response is the helper's answer. Exactly one of Data or Error is meaningful.
type Response struct {
	OK    bool            `json:"ok"`
	Error *Error          `json:"error,omitempty"`
	Data  json.RawMessage `json:"data,omitempty"`
}

// Error is a structured failure returned by an operation.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return fmt.Sprintf("%s: %s", e.Code, e.Message) }

// Error codes shared by all operations.
const (
	CodeUnknownOp   = "unknown_op"
	CodeBadArgs     = "bad_args"
	CodeForbidden   = "forbidden"
	CodeFailed      = "failed"
	CodeBadRequest  = "bad_request"
	CodeUnavailable = "unavailable"
)

// ErrForbidden is returned when the connecting process is not allowed to call the helper.
var ErrForbidden = errors.New("caller not permitted")

// Errorf builds an *Error with the given code.
func Errorf(code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}
