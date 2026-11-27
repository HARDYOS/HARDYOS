package vms

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/ports"
)

func slotVM(id string, slot int, remote, all bool) *stored {
	return &stored{spec: Spec{ID: id, Name: id, Streaming: &Streaming{Sunshine: true, Remote: remote, Slot: slot, AllSlots: all}}}
}

// Port sets (decisions 506, 509): a VM keeps its own when free, else the
// lowest free one; never one another published VM has, nor one an app of
// this server holds a host port of (an app installed before the sets were
// reserved); a VM set up before the sets gets the standard set only.
func TestPickStreamingSlot(t *testing.T) {
	a := slotVM("a", 0, true, true)
	b := slotVM("b", 0, false, true)
	if s, err := pickStreamingSlot(b, []*stored{a, b}, nil); err != nil || s != 1 {
		t.Fatalf("slot %d %v", s, err)
	}
	app := map[string]bool{fmt.Sprintf("%d/udp", ports.StreamingSlot(1).UDP[0]): true}
	if s, err := pickStreamingSlot(b, []*stored{a, b}, app); err != nil || s != 2 {
		t.Fatalf("slot with an app on set 1: %d %v", s, err)
	}
	c := slotVM("c", 3, false, true)
	if s, _ := pickStreamingSlot(c, []*stored{a, c}, nil); s != 3 {
		t.Fatalf("its own set: %d", s)
	}
	old := slotVM("old", 0, false, false)
	if _, err := pickStreamingSlot(old, []*stored{a, old}, nil); err == nil || !strings.Contains(err.Error(), "standard streaming ports") {
		t.Fatalf("an old VM: %v", err)
	}
	busy := map[string]bool{fmt.Sprintf("%d/tcp", ports.StreamingSlot(0).Base): true}
	if _, err := pickStreamingSlot(old, []*stored{old}, busy); err == nil {
		t.Fatal("an old VM took the standard set an app holds a port of")
	}
	if slotAppPort(1, app) == "" || slotAppPort(0, app) != "" {
		t.Fatal("slotAppPort")
	}
}
