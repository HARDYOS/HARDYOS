package ports

import "testing"

func TestNoPortIsUsedTwice(t *testing.T) {
	seen := map[int]string{}
	for name, p := range Fixed {
		if p < 1024 || p > 65535 {
			t.Errorf("%s: %d isn't a valid unprivileged port", name, p)
		}
		if other, dup := seen[p]; dup {
			t.Errorf("%s and %s both use %d", name, other, p)
		}
		seen[p] = name
		if p >= AppProxyBase && p < AppProxyBase+AppProxyCount {
			t.Errorf("%s (%d) is inside the app window proxy range %d-%d", name, p, AppProxyBase, AppProxyBase+AppProxyCount-1)
		}
	}
}
