package vms

// The check of a cluster VM's domain XML before QEMU starts (decisions 351
// and 385): libvirt's qemu hook hands root the XML of an incoming
// migration ("migrate") and of every start ("prepare", "start",
// "restore"); a cluster VM's XML must match root's own rendering of the
// stored spec in everything that decides what QEMU touches and how it is
// confined.
//
// The comparison is per element: every element and attribute the
// rendering has must be there with the same value, and the incoming XML
// may add only what libvirt itself adds to a defined or running domain
// (aliases, addresses, generated socket paths under libvirt's own
// folders, its implicit controllers and PS/2 inputs), each allowlisted
// with a check of its value. Everything else is refused: a host device,
// an evdev or passthrough input, a disk with another cache or error
// policy, a network card with another filter, VLAN, ROM file or
// bandwidth, a security label other than libvirt's dynamic one, extra
// QEMU arguments.

import (
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"
)

// domainTop are the top-level elements an incoming domain may have: what
// HardyOS renders and what libvirt adds to a running domain by itself.
var domainTop = map[string]bool{
	"name": true, "uuid": true, "title": true, "description": true, "metadata": true, "memory": true,
	"currentMemory": true, "vcpu": true, "os": true, "features": true, "cpu": true, "clock": true,
	"on_poweroff": true, "on_reboot": true, "on_crash": true, "pm": true, "devices": true,
	"seclabel": true, "resource": true,
}

// rule says what an incoming element may have beyond the rendering's.
type rule struct {
	// attrs are attributes libvirt may add (absent from the rendering),
	// with a check of their value.
	attrs map[string]func(string) bool
	// kids are the rules for children the rendering has (default: exact).
	kids map[string]*rule
	// extra are children libvirt may add, with what they may hold.
	extra map[string]*rule
	// text: incoming text that may differ from the rendering's.
	text func(string) bool
}

func anyValue(string) bool { return true }

func oneOf(vals ...string) func(string) bool {
	return func(v string) bool {
		for _, x := range vals {
			if v == x {
				return true
			}
		}
		return false
	}
}

var digitsRE = regexp.MustCompile(`^[0-9]{1,10}$`)

func digits(v string) bool { return digitsRE.MatchString(v) }

var hexOrDigitsRE = regexp.MustCompile(`^(0x[0-9a-fA-F]{1,8}|[0-9]{1,10})$`)

func hexOrDigits(v string) bool { return hexOrDigitsRE.MatchString(v) }

var ptsRE = regexp.MustCompile(`^/dev/pts/[0-9]{1,6}$`)

func ptsPath(v string) bool { return ptsRE.MatchString(v) }

// libvirtPath: a socket libvirt makes for the domain in its own folders.
func libvirtPath(v string) bool {
	c := path.Clean(v)
	if c != v || strings.Contains(v, "..") {
		return false
	}
	return strings.HasPrefix(c, "/var/lib/libvirt/qemu/") || strings.HasPrefix(c, "/run/libvirt/qemu/")
}

var (
	aliasRule   = &rule{attrs: map[string]func(string) bool{"name": anyValue}}
	addressRule = &rule{attrs: map[string]func(string) bool{
		"type":   oneOf("pci", "drive", "virtio-serial", "usb", "isa", "ccw", "spapr-vio", "virtio-mmio"),
		"domain": hexOrDigits, "bus": hexOrDigits, "slot": hexOrDigits, "function": hexOrDigits,
		"multifunction": oneOf("on", "off"), "controller": hexOrDigits, "target": hexOrDigits, "unit": hexOrDigits,
		"port": anyValue, "reg": hexOrDigits, "iobase": hexOrDigits, "irq": hexOrDigits,
	}}
	// libvirt adds these to every device.
	deviceExtras = map[string]*rule{"alias": aliasRule, "address": addressRule}
)

func withExtras(more map[string]*rule) map[string]*rule {
	out := map[string]*rule{}
	for k, v := range deviceExtras {
		out[k] = v
	}
	for k, v := range more {
		out[k] = v
	}
	return out
}

// deviceRules are what libvirt may add to each kind of device HardyOS
// renders. A kind without a rule is compared exactly (with an alias and
// an address).
var deviceRules = map[string]*rule{
	// Disks: driver (cache, io, error policies), source, target, serial
	// and boot order exactly as rendered; libvirt adds a source index and
	// an empty backing store.
	"disk": {
		kids:  map[string]*rule{"source": {attrs: map[string]func(string) bool{"index": digits}}},
		extra: withExtras(map[string]*rule{"backingStore": {}}),
	},
	// Network cards: MAC, bridge, tap name, model and filter (with its
	// parameters) exactly; no VLAN, ROM, bandwidth or anything else that
	// wasn't rendered.
	"interface": {extra: withExtras(nil)},
	// The guest agent: libvirt binds the socket in its own folder.
	"channel": {
		kids: map[string]*rule{"target": {attrs: map[string]func(string) bool{"state": oneOf("connected", "disconnected")}}},
		extra: withExtras(map[string]*rule{"source": {attrs: map[string]func(string) bool{
			"mode": oneOf("bind"), "path": libvirtPath}}}),
	},
	// The console: a socket in libvirt's folder, never a network address.
	"graphics": {
		attrs: map[string]func(string) bool{"port": oneOf("-1", "0"), "autoport": oneOf("yes", "no"), "socket": libvirtPath},
		kids:  map[string]*rule{"listen": {attrs: map[string]func(string) bool{"socket": libvirtPath}}},
		extra: withExtras(nil),
	},
	"serial": {
		attrs: map[string]func(string) bool{"tty": ptsPath},
		kids: map[string]*rule{"target": {attrs: map[string]func(string) bool{"type": oneOf("isa-serial", "pci-serial", "system-serial")},
			extra: map[string]*rule{"model": {attrs: map[string]func(string) bool{"name": oneOf("isa-serial", "pci-serial", "pl011")}}}}},
		extra: withExtras(map[string]*rule{"source": {attrs: map[string]func(string) bool{"path": ptsPath}}}),
	},
	"console": {
		attrs: map[string]func(string) bool{"tty": ptsPath},
		extra: withExtras(map[string]*rule{"source": {attrs: map[string]func(string) bool{"path": ptsPath}}}),
	},
	"video": {
		kids:  map[string]*rule{"model": {attrs: map[string]func(string) bool{"vram": digits, "ram": digits, "vgamem": digits, "vram64": digits}}},
		extra: withExtras(nil),
	},
	"tpm": {
		kids:  map[string]*rule{"backend": {attrs: map[string]func(string) bool{"version": oneOf("2.0", "1.2")}}},
		extra: withExtras(nil),
	},
	"controller": {
		kids: map[string]*rule{},
		extra: withExtras(map[string]*rule{
			"model":  {attrs: map[string]func(string) bool{"name": anyValue}},
			"target": {attrs: map[string]func(string) bool{"chassisNr": digits, "chassis": digits, "port": hexOrDigits, "busNr": digits, "index": digits}},
			"driver": {attrs: map[string]func(string) bool{"queues": digits, "iothread": digits}},
		}),
		attrs: map[string]func(string) bool{"model": anyValue, "ports": digits, "vectors": digits},
	},
}

// implicitDevices are devices libvirt adds by itself that the rendering
// doesn't name, with what they may be.
var implicitDevices = map[string]func(n *xnode) error{
	"controller": func(n *xnode) error {
		switch n.Attrs["type"] {
		case "pci", "usb", "scsi", "sata", "virtio-serial", "ide", "fdc":
		default:
			return fmt.Errorf("an unexpected %s controller", n.Attrs["type"])
		}
		r := &rule{attrs: map[string]func(string) bool{"type": anyValue, "index": digits, "model": anyValue, "ports": digits, "vectors": digits},
			extra: deviceRules["controller"].extra}
		return extraOK(n, r, "controller")
	},
	"input": func(n *xnode) error {
		// The PS/2 mouse and keyboard every x86 machine has.
		if n.Attrs["bus"] != "ps2" || (n.Attrs["type"] != "mouse" && n.Attrs["type"] != "keyboard") {
			return fmt.Errorf("an unexpected %s input on %s", n.Attrs["type"], n.Attrs["bus"])
		}
		return extraOK(n, &rule{attrs: map[string]func(string) bool{"type": anyValue, "bus": anyValue}, extra: map[string]*rule{"alias": aliasRule}}, "input")
	},
	"audio": func(n *xnode) error {
		if n.Attrs["type"] != "none" {
			return fmt.Errorf("an unexpected %s audio backend", n.Attrs["type"])
		}
		return extraOK(n, &rule{attrs: map[string]func(string) bool{"type": anyValue, "id": digits}}, "audio")
	},
	"memballoon": func(n *xnode) error {
		if n.Attrs["model"] != "none" {
			return fmt.Errorf("an unexpected %s memory balloon", n.Attrs["model"])
		}
		return extraOK(n, &rule{attrs: map[string]func(string) bool{"model": anyValue}}, "memballoon")
	},
	"emulator": func(n *xnode) error {
		f := strings.TrimSpace(n.Text)
		if path.Clean(f) != f || path.Dir(f) != "/usr/bin" || !strings.HasPrefix(path.Base(f), "qemu-system-") || len(n.Attrs) > 0 || len(n.Children) > 0 {
			return fmt.Errorf("the emulator isn't the packaged QEMU")
		}
		return nil
	},
}

// extraOK checks an element libvirt added: only allowed attributes and
// children, and no text.
func extraOK(n *xnode, r *rule, where string) error {
	for k, v := range n.Attrs {
		ok := r.attrs[k]
		if ok == nil || !ok(v) {
			return fmt.Errorf("%s: unexpected %s=%q", where, k, v)
		}
	}
	if t := strings.TrimSpace(n.Text); t != "" && (r.text == nil || !r.text(t)) {
		return fmt.Errorf("%s: unexpected text", where)
	}
	for _, c := range n.Children {
		cr := r.extra[c.Name]
		if cr == nil {
			return fmt.Errorf("%s: unexpected <%s>", where, c.Name)
		}
		if err := extraOK(c, cr, where+"/"+c.Name); err != nil {
			return err
		}
	}
	return nil
}

// compare checks in against ex (the rendering) under r.
func compare(in, ex *xnode, r *rule, where string, bad func(string, ...any)) {
	if r == nil {
		r = &rule{}
	}
	for k, v := range ex.Attrs {
		if got, ok := in.Attrs[k]; !ok || got != v {
			bad("%s: %s is %q, expected %q", where, k, got, v)
		}
	}
	for k, v := range in.Attrs {
		if _, ok := ex.Attrs[k]; ok {
			continue
		}
		if ok := r.attrs[k]; ok == nil || !ok(v) {
			bad("%s: unexpected %s=%q", where, k, v)
		}
	}
	if it, et := strings.TrimSpace(in.Text), strings.TrimSpace(ex.Text); it != et && (r.text == nil || !r.text(it)) {
		bad("%s: %q differs from %q", where, it, et)
	}
	// Children: the k-th child of a name matches the rendering's k-th.
	seen := map[string]int{}
	exBy := map[string][]*xnode{}
	for _, c := range ex.Children {
		exBy[c.Name] = append(exBy[c.Name], c)
	}
	for _, c := range in.Children {
		i := seen[c.Name]
		seen[c.Name]++
		if c.Space != "" && c.Space != ex.Space {
			bad("%s: <%s> in another namespace", where, c.Name)
			continue
		}
		if i < len(exBy[c.Name]) {
			compare(c, exBy[c.Name][i], r.kids[c.Name], where+"/"+c.Name, bad)
			continue
		}
		er := r.extra[c.Name]
		if er == nil {
			bad("%s: unexpected <%s>", where, c.Name)
			continue
		}
		if err := extraOK(c, er, where+"/"+c.Name); err != nil {
			bad("%v", err)
		}
	}
	for name, l := range exBy {
		if seen[name] < len(l) {
			bad("%s: <%s> is missing", where, name)
		}
	}
}

// CheckMigrationXML accepts an incoming domain only when everything that
// decides what QEMU touches and how it is confined matches expected (the
// destination's own rendering of the stored spec).
func CheckMigrationXML(incoming, expected []byte) error {
	in, err := parseTree(incoming)
	if err != nil {
		return fmt.Errorf("the incoming domain XML: %w", err)
	}
	ex, err := parseTree(expected)
	if err != nil {
		return fmt.Errorf("the expected domain XML: %w", err)
	}
	var p Problems
	bad := func(format string, a ...any) {
		if len(p) < 40 {
			p = append(p, fmt.Sprintf(format, a...))
		}
	}
	if in.Name != "domain" || in.Space != "" {
		return Problems{"not a libvirt domain"}
	}
	if in.Attrs["type"] != ex.Attrs["type"] {
		bad("the hypervisor type differs")
	}
	for k, v := range in.Attrs {
		switch {
		case k == "type":
		case k == "id":
			if !digits(v) && v != "-1" {
				bad("the domain id isn't a number")
			}
		case strings.HasPrefix(k, "xmlns"):
			bad("the domain declares an XML namespace (%s)", k)
		default:
			bad("unexpected domain attribute %s", k)
		}
	}
	for _, c := range in.Children {
		if !domainTop[c.Name] {
			bad("unexpected element <%s>", c.Name)
		}
		if c.Space != "" && c.Name != "metadata" {
			bad("element <%s> in another namespace", c.Name)
		}
	}
	for _, f := range []string{"name", "uuid"} {
		if in.text(f) != ex.text(f) {
			bad("the domain's %s differs", f)
		}
	}
	if kib(in.child("memory")) != kib(ex.child("memory")) || kib(in.child("currentMemory")) > kib(ex.child("memory")) {
		bad("the memory size differs")
	}
	if in.text("vcpu") != ex.text("vcpu") {
		bad("the number of CPUs differs")
	}
	checkCPU(in.child("cpu"), ex.child("cpu"), bad)
	checkOS(in.child("os"), ex.child("os"), bad)
	checkSeclabels(in, ex, bad)
	if r := in.child("resource"); r != nil {
		if err := extraOK(r, &rule{extra: map[string]*rule{"partition": {text: oneOf("/machine")}}}, "resource"); err != nil {
			bad("%v", err)
		}
	}
	checkDevices(in.child("devices"), ex.child("devices"), bad)
	if len(p) > 0 {
		return p
	}
	return nil
}

// checkSeclabels: the domain is confined the way the destination confines
// every VM: libvirt's dynamic labels (AppArmor and DAC) that it generates
// itself, never a static or no label, never a base label of the source's
// choosing, never relabelling switched off. The rendering names no label,
// so these are the only ones that "equal" it.
func checkSeclabels(in, ex *xnode, bad func(string, ...any)) {
	if len(ex.all("seclabel")) > 0 {
		// HardyOS never renders one; if it ever does, compare exactly.
		for i, e := range ex.all("seclabel") {
			l := in.all("seclabel")
			if i >= len(l) {
				bad("a security label is missing")
				continue
			}
			compare(l[i], e, nil, "seclabel", bad)
		}
		return
	}
	for _, sl := range in.all("seclabel") {
		if sl.Attrs["type"] != "dynamic" {
			bad("the domain isn't confined by libvirt's dynamic label (%s)", sl.Attrs["type"])
		}
		if sl.Attrs["relabel"] == "no" {
			bad("relabelling is switched off")
		}
		if m := sl.Attrs["model"]; m != "apparmor" && m != "dac" {
			bad("unexpected security model %q", m)
		}
		r := &rule{attrs: map[string]func(string) bool{"type": anyValue, "model": anyValue, "relabel": oneOf("yes")},
			extra: map[string]*rule{"label": {text: anyValue}, "imagelabel": {text: anyValue}}}
		if err := extraOK(sl, r, "seclabel"); err != nil {
			bad("%v", err)
		}
	}
}

func kib(n *xnode) int64 {
	if n == nil {
		return -1
	}
	v, err := strconv.ParseInt(strings.TrimSpace(n.Text), 10, 64)
	if err != nil {
		return -1
	}
	switch strings.ToLower(n.Attrs["unit"]) {
	case "", "kib", "k":
		return v
	case "mib", "m":
		return v << 10
	case "gib", "g":
		return v << 20
	case "b", "bytes":
		return v >> 10
	}
	return -1
}

func checkCPU(in, ex *xnode, bad func(string, ...any)) {
	if ex == nil {
		return
	}
	if in == nil {
		bad("the CPU isn't described")
		return
	}
	if in.Attrs["mode"] != ex.Attrs["mode"] {
		bad("the CPU mode differs (%s, expected %s)", in.Attrs["mode"], ex.Attrs["mode"])
	}
	if em := ex.child("model"); em != nil {
		im := in.child("model")
		if im == nil || strings.TrimSpace(im.Text) != strings.TrimSpace(em.Text) {
			bad("the CPU model differs")
		}
	}
	it, et := in.child("topology"), ex.child("topology")
	if et != nil && (it == nil || it.Attrs["cores"] != et.Attrs["cores"] || it.Attrs["threads"] != et.Attrs["threads"]) {
		bad("the CPU topology differs")
	}
}

func checkOS(in, ex *xnode, bad func(string, ...any)) {
	if in == nil || ex == nil {
		bad("the boot settings aren't described")
		return
	}
	if et, it := ex.child("type"), in.child("type"); et == nil || it == nil || it.Attrs["arch"] != et.Attrs["arch"] {
		bad("the architecture differs")
	}
	for _, c := range in.Children {
		switch c.Name {
		case "type", "loader", "nvram", "bootmenu", "boot", "firmware", "smbios":
		case "kernel", "initrd", "cmdline", "dtb":
			bad("direct kernel boot isn't allowed")
		default:
			bad("unexpected boot element <%s>", c.Name)
		}
	}
	packaged := func(f string) bool {
		c := path.Clean(f)
		return c == f && strings.HasPrefix(c, "/usr/share/")
	}
	// The firmware is libvirt's choice of the packaged files; the NVRAM
	// must be the VM's own file, made from a packaged template.
	if l := in.child("loader"); l != nil {
		if f := strings.TrimSpace(l.Text); f != "" && !packaged(f) {
			bad("the firmware isn't a packaged file")
		}
	}
	en, inv := ex.text("nvram"), in.child("nvram")
	switch {
	case en == "" && inv != nil && strings.TrimSpace(inv.Text) != "":
		bad("unexpected NVRAM file")
	case en != "" && (inv == nil || path.Clean(strings.TrimSpace(inv.Text)) != en):
		bad("the NVRAM file differs")
	}
	if inv != nil {
		if inv.Attrs["type"] != "" && inv.Attrs["type"] != "file" {
			bad("the NVRAM isn't a file")
		}
		if t := inv.Attrs["template"]; t != "" && !packaged(t) {
			bad("the NVRAM template isn't a packaged file")
		}
		if inv.child("source") != nil {
			bad("the NVRAM has a source")
		}
	}
}

// deviceKey matches an incoming device with the rendering's: disks by
// target, network cards by MAC, controllers by type and index, anything
// else by its place among devices of its kind.
func deviceKey(n *xnode, nth int) string {
	switch n.Name {
	case "disk":
		if t := n.child("target"); t != nil {
			return "disk|" + t.Attrs["dev"]
		}
	case "interface":
		if m := n.child("mac"); m != nil {
			return "interface|" + strings.ToLower(m.Attrs["address"])
		}
	case "controller":
		return "controller|" + n.Attrs["type"] + "|" + n.Attrs["index"]
	case "input":
		return "input|" + n.Attrs["type"] + "|" + n.Attrs["bus"]
	}
	return n.Name + "|#" + strconv.Itoa(nth)
}

func checkDevices(in, ex *xnode, bad func(string, ...any)) {
	if in == nil || ex == nil {
		bad("the devices aren't described")
		return
	}
	exBy := map[string]*xnode{}
	count := map[string]int{}
	for _, d := range ex.Children {
		k := deviceKey(d, count[d.Name])
		count[d.Name]++
		exBy[k] = d
	}
	matched := map[string]bool{}
	count = map[string]int{}
	for _, d := range in.Children {
		if d.Space != "" {
			bad("a device in another namespace (<%s>)", d.Name)
			continue
		}
		k := deviceKey(d, count[d.Name])
		count[d.Name]++
		if e, ok := exBy[k]; ok && !matched[k] {
			matched[k] = true
			if d.Name == "input" && (d.Attrs["type"] == "evdev" || d.Attrs["type"] == "passthrough") {
				bad("an %s input reads the host's devices", d.Attrs["type"])
			}
			r := deviceRules[d.Name]
			if r == nil {
				r = &rule{extra: withExtras(nil)}
			}
			compare(d, e, r, d.Name, bad)
			continue
		}
		if f := implicitDevices[d.Name]; f != nil {
			if err := f(d); err != nil {
				bad("%v", err)
			}
			continue
		}
		bad("unexpected device <%s>", d.Name)
	}
	for k := range exBy {
		if !matched[k] {
			bad("the device %s is missing", k)
		}
	}
}
