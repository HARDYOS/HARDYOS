package priv

import (
	"context"
	"encoding/json"
	"os"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/version"
)

// Operation names. Every privileged action HardyOS can take is listed here.
const (
	OpPing = "system.ping"
)

// PingResult is returned by system.ping.
type PingResult struct {
	Version  string    `json:"version"`
	Hostname string    `json:"hostname"`
	Time     time.Time `json:"time"`
	EUID     int       `json:"euid"`
	// Started is when this hardyd-priv started: hardyd's monitor notices
	// restarts by it changing.
	Started time.Time `json:"started"`
}

// started is when this process began.
var started = time.Now().UTC()

// RegisterBuiltins adds the operations that ship with this build.
func RegisterBuiltins(s *Server) {
	s.Handle(OpPing, func(ctx context.Context, _ json.RawMessage) (any, error) {
		host, _ := os.Hostname()
		return PingResult{
			Version:  version.Version,
			Hostname: host,
			Time:     time.Now().UTC(),
			EUID:     os.Geteuid(),
			Started:  started,
		}, nil
	})
}
