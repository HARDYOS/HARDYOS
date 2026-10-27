package devices

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// hostHelpers keep GPU device files open on the server's behalf and are
// stopped (and started again) by HardyOS itself while a GPU changes hands.
var hostHelpers = map[string]string{"nvidia-persistenced": "nvidia-persistenced.service"}

// gpuNodes are the device files that belong to the card in addr's slot.
func (h *Host) gpuNodes(addr string) []string {
	var nodes []string
	entries, _ := os.ReadDir(h.path("/sys/bus/pci/devices"))
	for _, e := range entries {
		if slotOf(e.Name()) != slotOf(addr) || !pciAddrRE.MatchString(e.Name()) {
			continue
		}
		drm, _ := os.ReadDir(h.path(pciDev(e.Name()) + "/drm"))
		for _, d := range drm {
			if strings.HasPrefix(d.Name(), "card") || strings.HasPrefix(d.Name(), "renderD") {
				nodes = append(nodes, "/dev/dri/"+d.Name())
			}
		}
		for _, line := range strings.Split(h.readTrim("/proc/driver/nvidia/gpus/"+e.Name()+"/information"), "\n") {
			k, v, ok := strings.Cut(line, ":")
			if ok && strings.TrimSpace(k) == "Device Minor" {
				if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
					nodes = append(nodes, fmt.Sprintf("/dev/nvidia%d", n))
				}
			}
		}
	}
	sort.Strings(nodes)
	return nodes
}

var appSliceRE = regexp.MustCompile(`hardyos-app-([^/]+)\.slice`)

// deviceUsers lists processes that have one of the card's device files
// open (HardyOS's own helpers aside).
func (h *Host) deviceUsers(addr string) []DeviceUser {
	out := []DeviceUser{}
	nodes := h.gpuNodes(addr)
	if len(nodes) == 0 {
		return out
	}
	want := map[string]bool{}
	for _, n := range nodes {
		want[n] = true
	}
	for _, u := range h.openers(want) {
		if _, helper := hostHelpers[u.Process]; !helper {
			out = append(out, u)
		}
	}
	return out
}

// openers scans /proc for processes with any of the files open.
func (h *Host) openers(files map[string]bool) []DeviceUser {
	var out []DeviceUser
	procs, _ := os.ReadDir(h.path("/proc"))
	for _, p := range procs {
		pid, err := strconv.Atoi(p.Name())
		if err != nil {
			continue
		}
		dir := filepath.Join("/proc", p.Name())
		fds, err := os.ReadDir(h.path(dir + "/fd"))
		if err != nil {
			continue
		}
		hit := false
		for _, fd := range fds {
			if t, err := os.Readlink(h.path(dir + "/fd/" + fd.Name())); err == nil && files[t] {
				hit = true
				break
			}
		}
		if !hit {
			continue
		}
		u := DeviceUser{PID: pid, Process: h.readTrim(dir + "/comm")}
		cg := h.readTrim(dir + "/cgroup")
		if m := appSliceRE.FindStringSubmatch(cg); m != nil {
			u.App = strings.ReplaceAll(m[1], `\x2d`, "-")
		}
		u.Container = strings.Contains(cg, "docker-") || strings.Contains(cg, "/docker/")
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PID < out[j].PID })
	return out
}

// usersMessage explains who is using a GPU, for a refusal.
func usersMessage(gpu string, users []DeviceUser) string {
	var apps, others []string
	for _, u := range users {
		switch {
		case u.App != "":
			if !contains(apps, u.App) {
				apps = append(apps, u.App)
			}
		case u.Container:
			if !contains(others, "a Docker container ("+u.Process+")") {
				others = append(others, "a Docker container ("+u.Process+")")
			}
		default:
			if !contains(others, u.Process) {
				others = append(others, u.Process)
			}
		}
	}
	var who []string
	if len(apps) == 1 {
		who = append(who, "the app "+apps[0])
	} else if len(apps) > 1 {
		who = append(who, "the apps "+strings.Join(apps, ", "))
	}
	who = append(who, others...)
	return fmt.Sprintf("The graphics card %s is in use by %s right now. Stop %s first (App Store > Stop), then start the VM again.",
		gpu, strings.Join(who, " and "), map[bool]string{true: "it", false: "them"}[len(who) == 1])
}
