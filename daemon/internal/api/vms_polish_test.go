package api

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/vms"
)

func TestVMPolishAPI(t *testing.T) {
	env, stub := newVMEnv(t)
	admin := env.client(t)
	admin.do("POST", "/api/v1/setup/admin", map[string]string{"username": "cade", "password": "supersecret1"}, nil)
	admin.do("POST", "/api/v1/users", map[string]string{"username": "kid", "password": "kidpassword1"}, nil)
	kid := env.client(t)
	kid.do("POST", "/api/v1/auth/login", map[string]string{"username": "kid", "password": "kidpassword1"}, nil)

	for _, p := range []string{"/api/v1/vms/catalog", "/api/v1/vms/usertemplates"} {
		if code := kid.do("GET", p, nil, nil); code != 403 {
			t.Fatalf("a family member read %s: %d", p, code)
		}
	}
	var cat []vms.CatalogView
	if code := admin.do("GET", "/api/v1/vms/catalog", nil, &cat); code != 200 || len(cat) != 1 {
		t.Fatalf("catalog = %d %+v", code, cat)
	}

	// One-click Debian: the job fetches the verified image and the import
	// carries its checksum.
	req := linuxRequest()
	req.Spec.Template = "debian13"
	req.Spec.Disks[0].Import = nil
	req.Downloads = nil
	req.Catalog = "debian-13"
	var acc struct {
		Job struct {
			ID string `json:"id"`
		} `json:"job"`
	}
	if code := admin.do("POST", "/api/v1/vms", req, &acc); code != 202 {
		t.Fatalf("create = %d", code)
	}
	if j := waitJobDone(t, admin, acc.Job.ID); j["state"] != "succeeded" {
		t.Fatalf("job = %+v", j)
	}
	created := stub.called(priv.OpVMsCreate)[0]
	if !strings.Contains(created, `"import":{"file":"debian-13-genericcloud-amd64.qcow2","digest":"sha512:aaaa`) {
		t.Fatalf("create = %s", created)
	}
	// A verified image and another image for the same disk: refused.
	bad := linuxRequest()
	bad.Catalog = "debian-13"
	if code := admin.do("POST", "/api/v1/vms", bad, nil); code != 400 {
		t.Fatalf("catalog + import = %d", code)
	}
	// An unattended Windows install needs its password.
	win := VMCreateRequest{Spec: vms.Spec{ID: "win", Name: "Win", Template: "windows11", OS: "windows", Pool: "tank",
		CPU: vms.CPU{Cores: 2}, Memory: vms.Memory{MB: 4096}, Disks: []vms.Disk{{Name: "disk0", SizeGB: 64}},
		Media:    []vms.Media{{Kind: vms.MediaISO, ISO: "Win11.iso"}, {Kind: vms.MediaUnattend}},
		NICs:     []vms.NIC{{Mode: vms.NICNAT}},
		Unattend: &vms.Unattend{User: "cade", Locale: "en-US", Hooks: []string{"anything"}}}}
	if code := admin.do("POST", "/api/v1/vms", win, nil); code != 400 {
		t.Fatalf("unattended without a password = %d", code)
	}
	win.Password = "Windows pass 1"
	var acc2 struct {
		Job struct {
			ID     string          `json:"id"`
			Params json.RawMessage `json:"params"`
		} `json:"job"`
	}
	if code := admin.do("POST", "/api/v1/vms", win, &acc2); code != 202 {
		t.Fatalf("unattended create = %d", code)
	}
	if strings.Contains(string(acc2.Job.Params), "Windows pass") {
		t.Fatal("the Windows password is in the job's parameters")
	}
	waitJobDone(t, admin, acc2.Job.ID)

	// Schedules, checked here and by root.
	if code := admin.do("PUT", "/api/v1/vms/web/schedule", VMScheduleRequest{Schedule: vms.Schedule{Hourly: 500}}, nil); code != 400 {
		t.Fatalf("500 hourly = %d", code)
	}
	if code := admin.do("PUT", "/api/v1/vms/web/schedule", VMScheduleRequest{Schedule: vms.Schedule{Daily: 7}}, &acc); code != 202 {
		t.Fatalf("schedule = %d", code)
	}
	waitJobDone(t, admin, acc.Job.ID)
	if c := stub.called(priv.OpVMsScheduleSet); len(c) != 1 || !strings.Contains(c[0], `"daily":7`) {
		t.Fatalf("schedule calls = %v", c)
	}
	if code := kid.do("PUT", "/api/v1/vms/web/schedule", VMScheduleRequest{Schedule: vms.Schedule{Daily: 7}}, nil); code != 403 {
		t.Fatalf("a family member set a schedule: %d", code)
	}

	// USB: vendor:product only, running VMs only.
	if code := admin.do("POST", "/api/v1/vms/web/usb", VMUSBRequest{Device: "1-4.2"}, nil); code != 400 {
		t.Fatalf("usb port = %d", code)
	}
	stub.mu.Lock()
	stub.vms["web"].State = "stopped"
	stub.mu.Unlock()
	if code := admin.do("POST", "/api/v1/vms/web/usb", VMUSBRequest{Device: "046d:c52b"}, nil); code != 409 {
		t.Fatalf("usb into a stopped VM = %d", code)
	}
	// Templates need the VM off; deleting one needs its name.
	if code := admin.do("POST", "/api/v1/vms/web/template", VMMakeTemplateRequest{TemplateID: "Bad Name", Name: "x"}, nil); code != 400 {
		t.Fatalf("bad template id = %d", code)
	}
	if code := admin.do("POST", "/api/v1/vms/web/template", VMMakeTemplateRequest{TemplateID: "base", Name: "Base"}, &acc); code != 202 {
		t.Fatalf("make template = %d", code)
	}
	waitJobDone(t, admin, acc.Job.ID)
	if code := admin.do("DELETE", "/api/v1/vms/usertemplates/base", VMTemplateDeleteRequest{}, nil); code != 400 {
		t.Fatalf("delete without confirm = %d", code)
	}
	if code := admin.do("DELETE", "/api/v1/vms/usertemplates/base", VMTemplateDeleteRequest{Confirm: "Base"}, &acc); code != 202 {
		t.Fatalf("delete template = %d", code)
	}
}
