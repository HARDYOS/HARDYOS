// Package version holds build information injected at link time.
package version

import "runtime"

// Set with -ldflags "-X github.com/hardyos/hardyos/daemon/internal/version.Version=..."
var (
	Version = "0.0.0-dev"
	Commit  = "unknown"
)

// Info is the build information reported by the API and CLI.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	GoVersion string `json:"goVersion"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

// Get returns the current build information.
func Get() Info {
	return Info{
		Version:   Version,
		Commit:    Commit,
		GoVersion: runtime.Version(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
	}
}
