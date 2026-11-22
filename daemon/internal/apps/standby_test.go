package apps

import (
	"testing"

	portreg "github.com/hardyos/hardyos/daemon/internal/ports"
)

// The NetBird standby's fixed ports are kept from every app but their owner
// (decision 420).
func TestOwnedPortsKept(t *testing.T) {
	for _, p := range []int{portreg.NetBirdStandbyHTTP, portreg.NetBirdStandbyHTTPS, portreg.NetBirdStandbySTUN} {
		if keptPort(p, portreg.NetBirdStandbyApp) {
			t.Errorf("%d kept from its owner", p)
		}
		for _, other := range []string{"jellyfin", ""} {
			if !keptPort(p, other) {
				t.Errorf("%d given to %q", p, other)
			}
		}
	}
	if !keptPort(portreg.AppGateway, portreg.NetBirdStandbyApp) || !keptPort(2049, portreg.NetBirdStandbyApp) {
		t.Fatal("the owner got another HardyOS port")
	}
	if keptPort(8096, "jellyfin") {
		t.Fatal("an ordinary port is kept")
	}
}
