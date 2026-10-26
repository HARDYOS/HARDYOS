package apps

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

const dataDir = "/mnt/tank/apps/notes/data"

func testMF(t *testing.T, perms string) Manifest {
	t.Helper()
	var m Manifest
	src := strings.Replace(testManifest, `"folders"`, perms+`"folders"`, 1)
	if err := json.Unmarshal([]byte(src), &m); err != nil {
		t.Fatal(err)
	}
	m.Ports = append(m.Ports, Port{Name: "DNS", Label: "DNS", Default: 5300, Protocol: "udp"})
	return m
}

// resolved builds compose JSON with one service "app" whose options are svc.
func resolved(t *testing.T, svc string, extra string) Resolved {
	t.Helper()
	src := `{"name":"hardyos-notes","services":{"app":{"image":"ghcr.io/x/app:1",` + svc + `}` +
		`,"db":{"image":"postgres:16"}}` + extra + `}`
	src = strings.Replace(src, `,}`, `}`, -1)
	r, err := ParseResolved([]byte(src))
	if err != nil {
		t.Fatalf("%v in %s", err, src)
	}
	return r
}

var ports = map[string]int{"WEB": 8101, "DNS": 5301}

func TestPolicyAllowsAPlainApp(t *testing.T) {
	r := resolved(t, `"ports":[{"mode":"ingress","target":80,"published":"8101","protocol":"tcp"},{"target":53,"published":"5301","protocol":"udp"}],
		"volumes":[{"type":"bind","source":"`+dataDir+`/files","target":"/files","bind":{"create_host_path":true}},{"type":"tmpfs","target":"/tmp"},{"type":"volume","target":"/cache"}],
		"environment":{"A":"b"},"depends_on":{"db":{"condition":"service_healthy"}},"networks":{"default":null},
		"security_opt":["no-new-privileges:true"],"sysctls":{"net.ipv4.ip_forward":"1"},"cap_add":["NET_ADMIN"],
		"devices":[{"source":"/dev/net/tun","target":"/dev/net/tun","permissions":"rwm"}],"network_mode":"","volumes_from":["db"],
		"post_start":[{"command":["echo","hi"]}]`,
		`,"networks":{"default":{"name":"hardyos-notes_default","ipam":{}}}`)
	m := testMF(t, `"permissions":{"capabilities":["NET_ADMIN"],"devices":["/dev/net/tun"]},`)
	if err := r.Check(m, "hardyos-notes", dataDir, ports); err != nil {
		t.Fatal(err)
	}
	svc := r["services"].(map[string]any)["app"].(map[string]any)
	labels := svc["labels"].(map[string]any)
	if svc["restart"] != "unless-stopped" || labels["org.hardyos.app"] != "notes" || labels["org.hardyos.app.version"] != "1.0.0" {
		t.Errorf("HardyOS settings: %v", svc)
	}
	if got := r.BindSources(); len(got) != 1 || got[0] != dataDir+"/files" {
		t.Errorf("bind sources: %v", got)
	}
	if s := r.Services(); len(s) != 2 || s[0].Service != "app" || s[1].Image != "postgres:16" {
		t.Errorf("services: %v", s)
	}
	if d := DescribePermissions(m); len(d) != 2 || !strings.Contains(d[0], "NET_ADMIN") || !strings.Contains(d[1], "VPN") {
		t.Errorf("permissions: %v", d)
	}
}

func TestPolicyRefuses(t *testing.T) {
	m := testMF(t, "")
	cases := map[string]struct{ svc, extra, want string }{
		"privileged":         {svc: `"privileged":true`, want: "privileged"},
		"host network":       {svc: `"network_mode":"host"`, want: "network_mode: host"},
		"other container":    {svc: `"network_mode":"container:abc"`, want: "network_mode"},
		"host pid":           {svc: `"pid":"host"`, want: "pid: host"},
		"host ipc":           {svc: `"ipc":"host"`, want: "ipc: host"},
		"host uts":           {svc: `"uts":"host"`, want: "uts: host"},
		"host cgroup":        {svc: `"cgroup":"host"`, want: "cgroup"},
		"build":              {svc: `"build":{"context":"."}`, want: "published images"},
		"container name":     {svc: `"container_name":"x"`, want: "names the containers"},
		"unknown option":     {svc: `"frobnicate":1`, want: "frobnicate"},
		"docker socket":      {svc: `"volumes":[{"type":"bind","source":"/var/run/docker.sock","target":"/var/run/docker.sock"}]`, want: "outside the app's data folder"},
		"escape with dots":   {svc: `"volumes":[{"type":"bind","source":"` + dataDir + `/../../../etc","target":"/x"}]`, want: "outside"},
		"sibling dir":        {svc: `"volumes":[{"type":"bind","source":"` + dataDir + `-evil","target":"/x"}]`, want: "outside"},
		"relative bind":      {svc: `"volumes":[{"type":"bind","source":"data","target":"/x"}]`, want: "outside"},
		"shared propagation": {svc: `"volumes":[{"type":"bind","source":"` + dataDir + `/x","target":"/x","bind":{"propagation":"rshared"}}]`, want: "propagation"},
		"named volume":       {svc: `"volumes":[{"type":"volume","source":"data","target":"/x"}]`, want: "named volume"},
		"npipe":              {svc: `"volumes":[{"type":"npipe","source":"x","target":"/x"}]`, want: "npipe mounts"},
		"top volumes":        {extra: `,"volumes":{"data":{}}`, want: "named volumes"},
		"undeclared cap":     {svc: `"cap_add":["NET_ADMIN"]`, want: "isn't declared"},
		"forbidden cap":      {svc: `"cap_add":["SYS_ADMIN"]`, want: "SYS_ADMIN isn't available"},
		"all caps":           {svc: `"cap_add":["ALL"]`, want: "ALL isn't available"},
		"undeclared device":  {svc: `"devices":[{"source":"/dev/sda","target":"/dev/sda"}]`, want: "/dev/sda"},
		"unconfined":         {svc: `"security_opt":["seccomp=unconfined"]`, want: "security_opt"},
		"apparmor":           {svc: `"security_opt":["apparmor:unconfined"]`, want: "security_opt"},
		"kernel sysctl":      {svc: `"sysctls":{"kernel.shmmax":"1"}`, want: "kernel.shmmax"},
		"other port":         {svc: `"ports":[{"target":22,"published":"22","protocol":"tcp"}]`, want: "22/tcp"},
		"wrong protocol":     {svc: `"ports":[{"target":80,"published":"8101","protocol":"udp"}]`, want: "8101/udp"},
		"random port":        {svc: `"ports":[{"target":80,"protocol":"tcp"}]`, want: "manifest's ports"},
		"volumes_from host":  {svc: `"volumes_from":["container:other"]`, want: "volumes_from"},
		"syslog":             {svc: `"logging":{"driver":"syslog"}`, want: "logging driver"},
		"gpu":                {svc: `"deploy":{"resources":{"reservations":{"devices":[{"capabilities":["gpu"]}]}}}`, want: "GPUs"},
		"privileged hook":    {svc: `"post_start":[{"command":["sh"],"privileged":true}]`, want: "hooks"},
		"low oom":            {svc: `"oom_score_adj":-1000`, want: "oom_score_adj"},
		"external network":   {extra: `,"networks":{"lan":{"name":"lan","external":true}}`, want: "outside the app"},
		"macvlan":            {extra: `,"networks":{"lan":{"name":"hardyos-notes_lan","driver":"macvlan"}}`, want: "bridge"},
		"driver opts":        {extra: `,"networks":{"lan":{"name":"hardyos-notes_lan","driver_opts":{"com.docker.network.bridge.name":"br0"}}}`, want: "driver_opts"},
		"top-level secrets":  {extra: `,"secrets":{"x":{"file":"/etc/shadow"}}`, want: `"secrets"`},
	}
	for name, c := range cases {
		r := resolved(t, c.svc, c.extra)
		err := r.Check(m, "hardyos-notes", dataDir, ports)
		var all Problems
		errors.As(err, &all)
		if err == nil || !strings.Contains(strings.Join(all, "\n"), c.want) {
			t.Errorf("%s: got %v, want a problem mentioning %q", name, err, c.want)
		}
	}
}

func TestInsideDir(t *testing.T) {
	for p, want := range map[string]bool{
		dataDir: true, dataDir + "/a/b": true, dataDir + "/../data/x": true,
		dataDir + "/..": false, "/mnt/tank/apps/notes/data2": false, "/": false, "": false, "data/x": false,
	} {
		if got := insideDir(dataDir, p); got != want {
			t.Errorf("insideDir(%q) = %v", p, got)
		}
	}
}
