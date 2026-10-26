package apps

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// The policy below is checked against the compose file as Docker Compose
// resolves it (docker compose config --format json): includes, extends,
// env files and variables are already applied, so what's checked is exactly
// what runs. Anything not explicitly allowed is refused.

// AllowedCapabilities are the Linux capabilities an app may add, with what
// each lets it do (shown in the install dialog). Capabilities that amount to
// root on the host (SYS_ADMIN, SYS_MODULE, SYS_PTRACE, DAC_READ_SEARCH, BPF,
// SYS_RAWIO, SYS_TIME, ...) are never available.
var AllowedCapabilities = map[string]string{
	"NET_ADMIN":        "Change its own network settings (VPN apps)",
	"NET_RAW":          "Send raw network packets (ping, network tools)",
	"NET_BIND_SERVICE": "Listen on ports below 1024 inside the container",
	"NET_BROADCAST":    "Send network broadcasts",
	"CHOWN":            "Change file owners in its own folders",
	"DAC_OVERRIDE":     "Ignore file permissions in its own folders",
	"FOWNER":           "Act as the owner of its own files",
	"FSETID":           "Keep set-ID bits on its own files",
	"SETUID":           "Switch user inside the container",
	"SETGID":           "Switch group inside the container",
	"SETPCAP":          "Drop capabilities from its own processes",
	"KILL":             "Signal its own processes",
	"SYS_NICE":         "Raise the priority of its own processes",
	"SYS_RESOURCE":     "Raise its own resource limits",
	"SYS_CHROOT":       "Use chroot inside the container",
	"IPC_LOCK":         "Lock memory (some databases)",
	"MKNOD":            "Create device files inside the container",
	"AUDIT_WRITE":      "Write to the audit log (SSH servers)",
	"WAKE_ALARM":       "Set wake-up timers",
}

// devicePatterns are host devices an app may use, with what each is for.
var devicePatterns = []struct {
	re   *regexp.Regexp
	what string
}{
	{regexp.MustCompile(`^/dev/net/tun$`), "Network tunnels (VPN apps)"},
	{regexp.MustCompile(`^/dev/dri(/(card|renderD)[0-9]{1,3})?$`), "The graphics chip, for hardware video transcoding"},
	{regexp.MustCompile(`^/dev/fuse$`), "FUSE file systems inside the app"},
	{regexp.MustCompile(`^/dev/tty(USB|ACM)[0-9]{1,2}$`), "A USB serial device (e.g. a Zigbee or Z-Wave stick)"},
	{regexp.MustCompile(`^/dev/serial/by-id/[A-Za-z0-9][A-Za-z0-9._:-]{0,120}$`), "A USB serial device (e.g. a Zigbee or Z-Wave stick)"},
	{regexp.MustCompile(`^/dev/bus/usb$`), "USB devices"},
	{regexp.MustCompile(`^/dev/snd$`), "Sound devices"},
}

func deviceAllowed(path string) (string, bool) {
	for _, d := range devicePatterns {
		if d.re.MatchString(path) {
			return d.what, true
		}
	}
	return "", false
}

// DescribePermissions lists, in plain words, what the app may do beyond a
// plain container, for the install dialog.
func DescribePermissions(m Manifest) []string {
	out := []string{}
	for _, c := range m.Permissions.Capabilities {
		out = append(out, fmt.Sprintf("%s (%s)", AllowedCapabilities[c], c))
	}
	for _, d := range m.Permissions.Devices {
		what, _ := deviceAllowed(d)
		out = append(out, fmt.Sprintf("%s (%s)", what, d))
	}
	return out
}

// serviceKeys are the service options apps may use. Options with safety
// rules are checked in checkService; every other option is refused.
var serviceKeys = map[string]bool{
	// checked below
	"image": true, "ports": true, "volumes": true, "devices": true, "cap_add": true,
	"privileged": true, "network_mode": true, "networks": true, "security_opt": true,
	"sysctls": true, "pid": true, "ipc": true, "uts": true, "cgroup": true,
	"volumes_from": true, "logging": true, "deploy": true, "restart": true, "labels": true,
	// plain container settings
	"annotations": true, "attach": true, "cap_drop": true, "command": true, "cpu_count": true,
	"cpu_percent": true, "cpu_period": true, "cpu_quota": true, "cpu_rt_period": true, "cpu_rt_runtime": true,
	"cpu_shares": true, "cpus": true, "cpuset": true, "depends_on": true, "dns": true, "dns_opt": true,
	"dns_search": true, "domainname": true, "entrypoint": true, "environment": true, "expose": true,
	"extra_hosts": true, "group_add": true, "healthcheck": true, "hostname": true, "init": true,
	"links": true, "mac_address": true, "mem_limit": true, "mem_reservation": true, "mem_swappiness": true,
	"memswap_limit": true, "oom_kill_disable": true, "oom_score_adj": true, "pids_limit": true,
	"platform": true, "profiles": true, "pull_policy": true, "read_only": true, "scale": true,
	"shm_size": true, "stdin_open": true, "stop_grace_period": true, "stop_signal": true, "tmpfs": true,
	"tty": true, "ulimits": true, "user": true, "working_dir": true, "post_start": true, "pre_stop": true,
}

var refusedHint = map[string]string{
	"build":                 "apps must use published images (no build)",
	"container_name":        "HardyOS names the containers itself",
	"device_cgroup_rules":   "device rules aren't available to apps",
	"env_file":              "env files must be inside the app",
	"external_links":        "apps can't link to containers outside the app",
	"gpus":                  "GPU reservations aren't available to apps yet",
	"runtime":               "custom container runtimes aren't available to apps",
	"secrets":               "use settings instead of compose secrets",
	"configs":               "use settings instead of compose configs",
	"storage_opt":           "storage options aren't available to apps",
	"userns_mode":           "user namespace options aren't available to apps",
	"cgroup_parent":         "cgroup options aren't available to apps",
	"isolation":             "isolation options aren't available to apps",
	"credential_spec":       "credential specs aren't available to apps",
	"blkio_config":          "block I/O options aren't available to apps",
	"device_read_bps":       "block I/O options aren't available to apps",
	"use_api_socket":        "apps can't use the Docker API",
	"provider":              "service providers aren't available to apps",
	"models":                "models aren't available to apps",
	"develop":               "development options aren't available to apps",
	"label_file":            "label files aren't available to apps",
	"volume_driver":         "volume drivers aren't available to apps",
	"memswap":               "use memswap_limit",
	"container_name_prefix": "HardyOS names the containers itself",
}

// Resolved is a compose project after `docker compose config --format json`.
type Resolved map[string]any

// Check enforces the policy. dataDir is the app's data folder (every bind
// mount must be inside it) and ports the host port allotted to each of the
// manifest's ports. It also fills in what HardyOS always sets: a restart
// policy and a label naming the app.
func (r Resolved) Check(m Manifest, project, dataDir string, ports map[string]int) error {
	var p Problems
	for k := range r {
		switch k {
		case "name", "services", "networks":
		case "volumes":
			if vols, _ := r[k].(map[string]any); len(vols) > 0 {
				p.addf("named volumes aren't allowed: keep data in folders under ${HARDY_APP_DATA}, which HardyOS can snapshot")
			}
		default:
			if !strings.HasPrefix(k, "x-") {
				p.addf("top-level %q isn't allowed", k)
			}
		}
	}
	services, _ := r["services"].(map[string]any)
	if len(services) == 0 {
		p.addf("the compose file has no services")
	}
	if len(services) > 20 {
		p.addf("at most 20 services")
	}
	networks, _ := r["networks"].(map[string]any)
	for name, raw := range networks {
		n, _ := raw.(map[string]any)
		checkNetwork(&p, project, name, n)
	}

	// The host ports the app may publish, and which are still unused.
	allowed := map[string]string{} // "port/proto" -> port name
	for _, pt := range m.Ports {
		proto := pt.Protocol
		if proto == "" {
			proto = "tcp"
		}
		allowed[strconv.Itoa(ports[pt.Name])+"/"+proto] = pt.Name
	}
	caps := setOf(m.Permissions.Capabilities)
	devices := setOf(m.Permissions.Devices)

	names := make([]string, 0, len(services))
	for n := range services {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		svc, ok := services[name].(map[string]any)
		if !ok {
			p.addf("service %s is malformed", name)
			continue
		}
		checkService(&p, name, svc, services, dataDir, allowed, caps, devices)
		// What HardyOS sets on every container.
		if rp, _ := svc["restart"].(string); rp == "" || rp == "no" {
			svc["restart"] = "unless-stopped"
		}
		labels, _ := svc["labels"].(map[string]any)
		if labels == nil {
			labels = map[string]any{}
		}
		labels["org.hardyos.app"] = m.ID
		labels["org.hardyos.app.version"] = m.Version
		svc["labels"] = labels
	}
	return p.err()
}

func checkNetwork(p *Problems, project, name string, n map[string]any) {
	for k, v := range n {
		switch k {
		case "name":
			if s, _ := v.(string); s != "" && !strings.HasPrefix(s, project+"_") {
				p.addf("network %s: custom network names aren't allowed", name)
			}
		case "driver":
			if s, _ := v.(string); s != "" && s != "bridge" {
				p.addf("network %s: only bridge networks are allowed (not %s)", name, s)
			}
		case "external":
			if b, _ := v.(bool); b {
				p.addf("network %s: apps can't join networks outside the app", name)
			}
		case "ipam", "internal", "enable_ipv6", "enable_ipv4", "labels", "attachable":
			if k == "ipam" {
				ipam, _ := v.(map[string]any)
				if d, _ := ipam["driver"].(string); d != "" && d != "default" {
					p.addf("network %s: custom IPAM drivers aren't allowed", name)
				}
			}
		default:
			p.addf("network %s: option %q isn't allowed", name, k)
		}
	}
}

func checkService(p *Problems, name string, svc map[string]any, services map[string]any, dataDir string,
	allowedPorts map[string]string, caps, devices map[string]bool) {
	keys := make([]string, 0, len(svc))
	for k := range svc {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if strings.HasPrefix(k, "x-") {
			continue
		}
		if !serviceKeys[k] {
			if hint, ok := refusedHint[k]; ok {
				p.addf("service %s: %s (%s)", name, k, hint)
			} else {
				p.addf("service %s: option %q isn't allowed", name, k)
			}
		}
	}

	if img, _ := svc["image"].(string); strings.TrimSpace(img) == "" {
		p.addf("service %s needs an image", name)
	}
	if b, _ := svc["privileged"].(bool); b {
		p.addf("service %s: privileged containers aren't allowed", name)
	}
	// Lifecycle hooks run commands in the container; they can't be privileged.
	for _, hook := range []string{"post_start", "pre_stop"} {
		for _, raw := range anyList(svc[hook]) {
			if h, _ := raw.(map[string]any); h != nil {
				if b, _ := h["privileged"].(bool); b {
					p.addf("service %s: privileged %s hooks aren't allowed", name, hook)
				}
			}
		}
	}
	if v, ok := svc["oom_score_adj"].(float64); ok && v < -500 {
		p.addf("service %s: oom_score_adj below -500 isn't allowed", name)
	}
	for _, c := range stringList(svc["cap_add"]) {
		c = strings.ToUpper(strings.TrimPrefix(strings.ToUpper(c), "CAP_"))
		if !caps[c] {
			if _, ok := AllowedCapabilities[c]; ok {
				p.addf("service %s: capability %s isn't declared in the manifest's permissions", name, c)
			} else {
				p.addf("service %s: capability %s isn't available to apps", name, c)
			}
		}
	}
	for _, raw := range anyList(svc["devices"]) {
		src := ""
		switch d := raw.(type) {
		case string:
			src, _, _ = strings.Cut(d, ":")
		case map[string]any:
			src, _ = d["source"].(string)
		}
		if !devices[src] {
			p.addf("service %s: device %s isn't declared in the manifest's permissions", name, src)
		}
	}
	modeOK := func(field string, allowHost bool) {
		v, _ := svc[field].(string)
		switch {
		case v == "":
		case strings.HasPrefix(v, "service:"):
			if _, ok := services[strings.TrimPrefix(v, "service:")]; !ok {
				p.addf("service %s: %s may only refer to services in this app", name, field)
			}
		case v == "host" && !allowHost:
			p.addf("service %s: %s: host isn't allowed", name, field)
		case v == "bridge" || v == "none" || v == "private" || v == "shareable" || v == "host" && allowHost:
		default:
			p.addf("service %s: %s %q isn't allowed", name, field, v)
		}
	}
	modeOK("network_mode", false)
	modeOK("pid", false)
	modeOK("ipc", false)
	modeOK("uts", false)
	if v, _ := svc["cgroup"].(string); v != "" && v != "private" {
		p.addf("service %s: cgroup %q isn't allowed", name, v)
	}
	for _, so := range stringList(svc["security_opt"]) {
		switch strings.ReplaceAll(strings.TrimSpace(so), "=", ":") {
		case "no-new-privileges", "no-new-privileges:true":
		default:
			p.addf("service %s: security_opt %q isn't allowed", name, so)
		}
	}
	if sc, ok := svc["sysctls"].(map[string]any); ok {
		for k := range sc {
			if !strings.HasPrefix(k, "net.") {
				p.addf("service %s: sysctl %s isn't allowed (only net.*)", name, k)
			}
		}
	}
	for _, vf := range stringList(svc["volumes_from"]) {
		ref := strings.TrimPrefix(vf, "service:")
		ref, _, _ = strings.Cut(ref, ":")
		if strings.HasPrefix(vf, "container:") {
			p.addf("service %s: volumes_from may only name services in this app", name)
		} else if _, ok := services[ref]; !ok {
			p.addf("service %s: volumes_from may only name services in this app", name)
		}
	}
	if lg, ok := svc["logging"].(map[string]any); ok {
		if d, _ := lg["driver"].(string); d != "" && d != "json-file" && d != "local" && d != "journald" && d != "none" {
			p.addf("service %s: logging driver %s isn't allowed", name, d)
		}
	}
	if dp, ok := svc["deploy"].(map[string]any); ok {
		for k, v := range dp {
			switch k {
			case "resources":
				res, _ := v.(map[string]any)
				if rv, ok := res["reservations"].(map[string]any); ok {
					if _, ok := rv["devices"]; ok {
						p.addf("service %s: device reservations (GPUs) aren't available to apps yet", name)
					}
				}
			case "replicas", "restart_policy", "labels":
			default:
				p.addf("service %s: deploy.%s isn't allowed", name, k)
			}
		}
	}

	for _, raw := range anyList(svc["ports"]) {
		pm, _ := raw.(map[string]any)
		published := fmt.Sprint(pm["published"])
		proto, _ := pm["protocol"].(string)
		if proto == "" {
			proto = "tcp"
		}
		if pm["published"] == nil || published == "" || published == "0" {
			p.addf("service %s: every published port must be one of the manifest's ports (use ${HARDY_PORT_<NAME>})", name)
			continue
		}
		if _, ok := allowedPorts[published+"/"+proto]; !ok {
			p.addf("service %s: port %s/%s isn't one of the manifest's ports", name, published, proto)
		}
		if mode, _ := pm["mode"].(string); mode != "" && mode != "ingress" && mode != "host" {
			p.addf("service %s: port mode %s isn't allowed", name, mode)
		}
	}

	for _, raw := range anyList(svc["volumes"]) {
		vm, _ := raw.(map[string]any)
		typ, _ := vm["type"].(string)
		src, _ := vm["source"].(string)
		switch typ {
		case "bind":
			if !insideDir(dataDir, src) {
				p.addf("service %s: %s is outside the app's data folder; mount folders under ${HARDY_APP_DATA}", name, src)
			}
			if b, ok := vm["bind"].(map[string]any); ok {
				if prop, _ := b["propagation"].(string); prop != "" && prop != "private" && prop != "rprivate" {
					p.addf("service %s: bind propagation %s isn't allowed", name, prop)
				}
			}
		case "tmpfs":
		case "volume":
			if src != "" {
				p.addf("service %s: named volume %s isn't allowed; mount a folder under ${HARDY_APP_DATA}", name, src)
			}
		default:
			p.addf("service %s: %s mounts aren't allowed", name, typ)
		}
	}
}

// insideDir reports whether p is dir or below it (lexically; Manager also
// resolves symlinks before every start).
func insideDir(dir, p string) bool {
	if p == "" || !filepath.IsAbs(p) {
		return false
	}
	rel, err := filepath.Rel(filepath.Clean(dir), filepath.Clean(p))
	return err == nil && rel != ".." && !strings.HasPrefix(rel, "../")
}

// BindSources lists the host folders the app mounts.
func (r Resolved) BindSources() []string {
	var out []string
	services, _ := r["services"].(map[string]any)
	for _, raw := range services {
		svc, _ := raw.(map[string]any)
		for _, v := range anyList(svc["volumes"]) {
			vm, _ := v.(map[string]any)
			if t, _ := vm["type"].(string); t == "bind" {
				if s, _ := vm["source"].(string); s != "" {
					out = append(out, s)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// Services lists the services and their images, sorted by name.
func (r Resolved) Services() []ServiceImage {
	services, _ := r["services"].(map[string]any)
	out := make([]ServiceImage, 0, len(services))
	for name, raw := range services {
		svc, _ := raw.(map[string]any)
		img, _ := svc["image"].(string)
		out = append(out, ServiceImage{Service: name, Image: img})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Service < out[j].Service })
	return out
}

// ServiceImage names one service and the image it runs.
type ServiceImage struct {
	Service string `json:"service"`
	Image   string `json:"image"`
}

// ParseResolved reads `docker compose config --format json` output.
func ParseResolved(b []byte) (Resolved, error) {
	var r Resolved
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("reading the resolved compose file: %w", err)
	}
	return r, nil
}

func setOf(xs []string) map[string]bool {
	m := map[string]bool{}
	for _, x := range xs {
		m[x] = true
	}
	return m
}

func anyList(v any) []any {
	l, _ := v.([]any)
	return l
}

func stringList(v any) []string {
	var out []string
	for _, x := range anyList(v) {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
