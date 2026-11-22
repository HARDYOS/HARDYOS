package priv

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
	"github.com/hardyos/hardyos/daemon/internal/vms"
)

// The catalog takes an image's name, never a link (decision 410).
func TestVMCatalogOps(t *testing.T) {
	fake := &sysexec.Fake{}
	pc := vmServer(t, fake)
	ctx := context.Background()
	var res VMCatalogResult
	if err := pc.Call(ctx, OpVMsCatalogList, nil, &res); err != nil || len(res.Images) < 4 {
		t.Fatalf("catalog = %+v %v", res, err)
	}
	var pe *Error
	err := pc.Call(ctx, OpVMsCatalogFetch, map[string]any{"image": "debian-13", "url": "https://evil.example/x.qcow2"}, nil)
	if !errors.As(err, &pe) || pe.Code != CodeBadArgs || !strings.Contains(pe.Message, "unknown field") {
		t.Fatalf("url field: %v", err)
	}
	err = pc.Call(ctx, OpVMsCatalogFetch, vms.FetchArgs{Image: "nope"}, nil)
	if !errors.As(err, &pe) || pe.Code != CodeBadArgs {
		t.Fatalf("unknown image: %v", err)
	}
	err = pc.Call(ctx, OpVMsUSBAttach, vms.USBArgs{ID: "web", Device: "1-4"}, nil)
	if !errors.As(err, &pe) || pe.Code != CodeBadArgs {
		t.Fatalf("usb port: %v", err)
	}
}
