package priv

import (
	"context"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/netbird"
	"github.com/hardyos/hardyos/daemon/internal/vms"
)

// VMNetBird tells the VM engine this server's NetBird interface, address
// and network, from root's own NetBird client (never from hardyd), for
// forwarding game streaming to NetBird peers (decision 404). Answers are
// kept for 10 seconds: `netbird status` isn't free.
func VMNetBird(m *netbird.Manager) func(context.Context) vms.NetBirdInfo {
	var mu sync.Mutex
	var last vms.NetBirdInfo
	var at time.Time
	return func(ctx context.Context) vms.NetBirdInfo {
		mu.Lock()
		defer mu.Unlock()
		if time.Since(at) < 10*time.Second {
			return last
		}
		st, err := m.Status(ctx)
		info := vms.NetBirdInfo{}
		if err == nil && st != nil && st.Connected {
			info = vms.NetBirdInfo{Connected: true, Interface: st.Interface, IP: st.IP, Network: st.Network}
			if info.Interface == "" {
				info.Interface = "wt0"
			}
		}
		last, at = info, time.Now()
		return info
	}
}
