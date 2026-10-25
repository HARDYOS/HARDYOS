// Command hardyctl is the HardyOS command-line tool for scripting and recovery.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/version"
)

const usage = `hardyctl: manage a HardyOS system

Usage:
  hardyctl [flags] <command>

Commands:
  version      print the hardyctl version
  status       show hardyd health and version
  priv-ping    check the root helper directly (run as root or hardyd)

Flags:
`

func main() {
	api := flag.String("api", envOr("HARDYOS_API", "http://127.0.0.1:8080"), "hardyd base URL")
	socket := flag.String("socket", priv.DefaultSocket, "hardyd-priv socket (for priv-ping)")
	flag.Usage = func() {
		fmt.Fprint(os.Stderr, usage)
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}

	var err error
	switch flag.Arg(0) {
	case "version":
		fmt.Printf("hardyctl %s (%s)\n", version.Version, version.Commit)
	case "status":
		err = status(*api)
	case "priv-ping":
		err = privPing(*socket)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", flag.Arg(0))
		flag.Usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func status(base string) error {
	client := &http.Client{Timeout: 5 * time.Second}
	for _, p := range []string{"/api/v1/health", "/api/v1/version"} {
		res, err := client.Get(base + p)
		if err != nil {
			return err
		}
		body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		res.Body.Close()
		if res.StatusCode != http.StatusOK {
			return fmt.Errorf("%s returned %s", p, res.Status)
		}
		var pretty map[string]any
		if json.Unmarshal(body, &pretty) == nil {
			out, _ := json.MarshalIndent(pretty, "", "  ")
			fmt.Printf("%s\n%s\n", p, out)
		}
	}
	return nil
}

func privPing(socket string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var res priv.PingResult
	if err := priv.NewClient(socket).Call(ctx, priv.OpPing, nil, &res); err != nil {
		return err
	}
	fmt.Printf("hardyd-priv %s on %s (euid %d) at %s\n", res.Version, res.Hostname, res.EUID, res.Time.Format(time.RFC3339))
	return nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
