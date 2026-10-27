package apps

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

// Resources an app gets: limits through its own systemd slice, and the
// server's GPU when it has one.

// SliceDir is where the apps' slices are written (under Root). /run, so a
// slice never outlives the boot that wrote it; hardyd-priv writes them
// again at start.
const SliceDir = "/run/systemd/system"

// SliceName is the systemd slice an app's containers run in. Dashes in a
// slice name mean nesting to systemd, so the id's dashes are escaped the
// way systemd-escape does: "apex-rmm" -> hardyos-app-apex\x2drmm.slice.
func SliceName(id string) string {
	return "hardyos-app-" + strings.ReplaceAll(id, "-", `\x2d`) + ".slice"
}

// checkLimits checks an app's limits against the server.
func (m *Manager) checkLimits(l Limits) error {
	var p Problems
	if l.MemoryMB != 0 {
		if l.MemoryMB < 64 || l.MemoryMB > 1<<24 {
			p.addf("memory limit: 64 MB or more (or 0 for none)")
		} else if have := m.memTotal() >> 20; have > 0 && uint64(l.MemoryMB) > have {
			p.addf("memory limit: this server has %d MB", have)
		}
	}
	if l.CPUs != 0 {
		if math.IsNaN(l.CPUs) || l.CPUs < 0.05 || l.CPUs > 1024 {
			p.addf("processor limit: 0.05 processors or more (or 0 for none)")
		} else if n := runtime.NumCPU(); l.CPUs > float64(n) {
			p.addf("processor limit: this server has %d processors", n)
		}
	}
	return p.err()
}

// sliceUnit is the slice file for an app's limits.
func sliceUnit(id string, l Limits) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "# Written by HardyOS for the app %s; change its limits in the App Store.\n", id)
	fmt.Fprintf(&b, "[Unit]\nDescription=HardyOS app %s\n\n[Slice]\nMemoryAccounting=yes\nCPUAccounting=yes\n", id)
	if l.MemoryMB > 0 {
		fmt.Fprintf(&b, "MemoryMax=%dM\n", l.MemoryMB)
	} else {
		b.WriteString("MemoryMax=infinity\n")
	}
	if l.CPUs > 0 {
		fmt.Fprintf(&b, "CPUQuota=%d%%\n", int(math.Round(l.CPUs*100)))
	} else {
		b.WriteString("CPUQuota=\n")
	}
	return b.Bytes()
}

// writeSlice writes the app's slice (when it changed) and has systemd
// read it again.
func (m *Manager) writeSlice(ctx context.Context, id string, l Limits) error {
	path := filepath.Join(m.sys(SliceDir), SliceName(id))
	want := sliceUnit(id, l)
	if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, want) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := writeFileAtomic(path, want, 0o644); err != nil {
		return err
	}
	if _, err := m.run(ctx, "systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("loading the app's limits: %w", err)
	}
	return nil
}

// removeSlice deletes the app's slice file.
func (m *Manager) removeSlice(ctx context.Context, id string) error {
	err := os.Remove(filepath.Join(m.sys(SliceDir), SliceName(id)))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	_, err = m.run(ctx, "systemctl", "daemon-reload")
	return err
}

// setCgroupParent puts every service in the app's slice. It runs after the
// policy check, which refuses cgroup_parent from the package itself.
func (r Resolved) setCgroupParent(slice string) {
	services, _ := r["services"].(map[string]any)
	for _, raw := range services {
		if svc, ok := raw.(map[string]any); ok {
			svc["cgroup_parent"] = slice
		}
	}
}

// bindMounts lists every bind mount of every service (the maps themselves).
func (r Resolved) bindMounts() []map[string]any {
	var out []map[string]any
	services, _ := r["services"].(map[string]any)
	names := make([]string, 0, len(services))
	for n := range services {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		svc, _ := services[n].(map[string]any)
		for _, v := range anyList(svc["volumes"]) {
			vm, _ := v.(map[string]any)
			if t, _ := vm["type"].(string); t == "bind" {
				out = append(out, vm)
			}
		}
	}
	return out
}

// gpuHardware is what the server has, found at runtime (any architecture:
// only device files are looked at).
type gpuHardware struct {
	// DRI: /dev/dri exists with at least one render node.
	DRI bool
	// NVIDIA: /dev/nvidia0 exists and the NVIDIA container toolkit is
	// installed (Docker needs it for NVIDIA reservations).
	NVIDIA bool
	// NVIDIANoToolkit: the card is there but the toolkit isn't.
	NVIDIANoToolkit bool
}

func (m *Manager) detectGPU() gpuHardware {
	var hw gpuHardware
	if nodes, _ := filepath.Glob(m.sys("/dev/dri/renderD*")); len(nodes) > 0 {
		hw.DRI = true
	}
	if _, err := os.Stat(m.sys("/dev/nvidia0")); err == nil {
		for _, p := range []string{"/usr/bin/nvidia-container-runtime-hook", "/usr/bin/nvidia-container-runtime", "/usr/bin/nvidia-ctk"} {
			if _, err := os.Stat(m.sys(p)); err == nil {
				hw.NVIDIA = true
			}
		}
		hw.NVIDIANoToolkit = !hw.NVIDIA
	}
	return hw
}

// adaptGPU fits the checked compose file to the server's hardware: graphics
// devices the server doesn't have and NVIDIA reservations without an NVIDIA
// card are dropped (an app never fails to install for lack of a GPU), and
// services given graphics devices join the group that owns them so a
// non-root process can open them. sys maps a device path to the host path
// (Root). It returns warnings for the install dialog.
func (r Resolved) adaptGPU(hw gpuHardware, sys func(string) string, appName string) []string {
	var warn []string
	services, _ := r["services"].(map[string]any)
	names := make([]string, 0, len(services))
	for n := range services {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		svc, _ := services[n].(map[string]any)
		if svc == nil {
			continue
		}
		if devs, ok := svc["devices"]; ok {
			var keep []any
			for _, raw := range anyList(devs) {
				src := ""
				switch d := raw.(type) {
				case string:
					src, _, _ = strings.Cut(d, ":")
				case map[string]any:
					src, _ = d["source"].(string)
				}
				if driRE.MatchString(src) {
					fi, err := os.Stat(sys(src))
					if err != nil || (src == "/dev/dri" && !hw.DRI) {
						if src == "/dev/kfd" {
							warn = append(warn, fmt.Sprintf("This server has no AMD compute device (%s), so %s runs without ROCm", src, appName))
						} else {
							warn = append(warn, fmt.Sprintf("This server has no graphics chip (%s), so %s runs without hardware acceleration", src, appName))
						}
						continue
					}
					if gid := deviceGroup(fi, sys); gid > 0 {
						addGroup(svc, gid)
					}
				}
				keep = append(keep, raw)
			}
			if len(keep) == 0 {
				delete(svc, "devices")
			} else {
				svc["devices"] = keep
			}
		}
		dp, _ := svc["deploy"].(map[string]any)
		res, _ := dp["resources"].(map[string]any)
		rv, _ := res["reservations"].(map[string]any)
		if _, ok := rv["devices"]; ok && !hw.NVIDIA {
			delete(rv, "devices")
			if len(rv) == 0 {
				delete(res, "reservations")
			}
			if len(res) == 0 {
				delete(dp, "resources")
			}
			if len(dp) == 0 {
				delete(svc, "deploy")
			}
			if hw.NVIDIANoToolkit {
				warn = append(warn, fmt.Sprintf("This server has an NVIDIA card but not the NVIDIA container toolkit, so %s runs without it", appName))
			} else {
				warn = append(warn, fmt.Sprintf("This server has no NVIDIA graphics card, so %s runs without one", appName))
			}
		}
	}
	return dedupe(warn)
}

// deviceGroup is the group owning a graphics device (the render group for
// /dev/dri; for the folder, its first render node's).
func deviceGroup(fi os.FileInfo, sys func(string) string) int {
	if fi.IsDir() {
		nodes, _ := filepath.Glob(sys("/dev/dri/renderD*"))
		if len(nodes) == 0 {
			return -1
		}
		var err error
		if fi, err = os.Stat(nodes[0]); err != nil {
			return -1
		}
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return int(st.Gid)
	}
	return -1
}

func addGroup(svc map[string]any, gid int) {
	g := strconv.Itoa(gid)
	groups := anyList(svc["group_add"])
	for _, x := range groups {
		if fmt.Sprint(x) == g {
			return
		}
	}
	svc["group_add"] = append(groups, g)
}

func dedupe(xs []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

// appendNew appends the strings not already in xs.
func appendNew(xs []string, more ...string) []string {
	for _, x := range more {
		if !contains(xs, x) {
			xs = append(xs, x)
		}
	}
	return xs
}
