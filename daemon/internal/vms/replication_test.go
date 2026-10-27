package vms

import (
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/devices"
)

func TestResetRestored(t *testing.T) {
	s := Spec{
		ID: "web", UUID: "11111111-2222-3333-4444-555555555555",
		Autostart: Autostart{Enabled: true},
		Devices:   []devices.Device{{}},
		NICs:      []NIC{{Mode: "bridge", MAC: "52:54:00:00:00:01", AllowSpoofing: true}},
		Streaming: &Streaming{},
		CloudInit: &CloudInit{},
		Media:     []Media{{Kind: "cloudinit"}, {Kind: "iso", ISO: "debian.iso"}},
	}
	notes := ResetRestored(&s)
	if s.Autostart.Enabled || len(s.Devices) != 0 || s.NICs[0].AllowSpoofing || s.Streaming != nil || s.CloudInit != nil {
		t.Fatalf("%+v", s)
	}
	if s.NICs[0].MAC == "52:54:00:00:00:01" || s.UUID == "11111111-2222-3333-4444-555555555555" || !uuidRE.MatchString(s.UUID) {
		t.Fatalf("MAC %s UUID %s", s.NICs[0].MAC, s.UUID)
	}
	if len(s.Media) != 1 || s.Media[0].Kind != "iso" {
		t.Fatalf("media %+v", s.Media)
	}
	all := strings.Join(notes, "; ")
	for _, w := range []string{"starts with the server", "host devices", "network filter", "MAC", "streaming", "cloud-init", "UUID"} {
		if !strings.Contains(all, w) {
			t.Errorf("notes don't mention %s: %s", w, all)
		}
	}
}
