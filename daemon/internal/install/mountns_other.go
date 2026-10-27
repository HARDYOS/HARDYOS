//go:build !linux

package install

func privateMountNS(fn func() error) error { return fn() }

// OtherNamespaceMounts needs Linux.
func OtherNamespaceMounts(target string) []string { return nil }
