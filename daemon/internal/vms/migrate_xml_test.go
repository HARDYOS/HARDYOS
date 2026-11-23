package vms

import (
	"strings"
	"testing"
)

// live dresses a rendering up the way libvirt shows a running domain:
// aliases, addresses, its implicit controllers and PS/2 inputs, generated
// socket paths and ptys.
func live(x string) string {
	r := strings.NewReplacer(
		`<source dev="`+testWWN+`"></source>`, `<source dev="`+testWWN+`" index="1"></source><backingStore/>`,
		`<serial>web-disk0</serial>`, `<serial>web-disk0</serial><alias name="scsi0-0-0-0"/><address type="drive" controller="0" bus="0" target="0" unit="0"/>`,
		`<filterref filter="clean-traffic"></filterref>`, `<filterref filter="clean-traffic"></filterref><alias name="net0"/><address type="pci" domain="0x0000" bus="0x01" slot="0x00" function="0x0"/>`,
		`<target type="virtio" name="org.qemu.guest_agent.0"></target>`, `<source mode="bind" path="/var/lib/libvirt/qemu/channel/target/domain-7-web/org.qemu.guest_agent.0"/><target type="virtio" name="org.qemu.guest_agent.0" state="connected"></target><alias name="channel0"/><address type="virtio-serial" controller="0" bus="0" port="1"/>`,
		`<graphics type="vnc">`, `<graphics type="vnc" socket="/var/lib/libvirt/qemu/domain-7-web/vnc.sock">`,
		`<listen type="socket"></listen>`, `<listen type="socket" socket="/var/lib/libvirt/qemu/domain-7-web/vnc.sock"></listen>`,
		`<serial type="pty">`, `<serial type="pty"><source path="/dev/pts/3"/>`,
		`<target port="0"></target>`, `<target type="isa-serial" port="0"><model name="isa-serial"/></target><alias name="serial0"/>`,
		`<console type="pty">`, `<console type="pty" tty="/dev/pts/3"><source path="/dev/pts/3"/>`,
		`<model type="virtio" heads="1" primary="yes"></model>`, `<model type="virtio" heads="1" primary="yes"></model><alias name="video0"/>`,
		`<stats period="5"></stats>`, `<stats period="5"></stats><alias name="balloon0"/>`,
		`</devices>`, `<controller type="pci" index="0" model="pcie-root"><alias name="pcie.0"/></controller>
<controller type="pci" index="1" model="pcie-root-port"><model name="pcie-root-port"/><target chassis="1" port="0x10"/><alias name="pci.1"/><address type="pci" domain="0x0000" bus="0x00" slot="0x02" function="0x0" multifunction="on"/></controller>
<controller type="virtio-serial" index="0"><alias name="virtio-serial0"/></controller>
<controller type="sata" index="0"><alias name="ide"/></controller>
<input type="mouse" bus="ps2"><alias name="input2"/></input><input type="keyboard" bus="ps2"/></devices>`,
	)
	return incoming(r.Replace(x))
}

func TestCheckAcceptsLibvirtsLiveView(t *testing.T) {
	exp := renderWeb(t)
	in := live(string(exp))
	if in == incoming(string(exp)) {
		t.Fatal("the live view changed nothing")
	}
	if err := CheckMigrationXML([]byte(in), exp); err != nil {
		t.Fatalf("libvirt's live view of the rendering: %v\n%s", err, in)
	}
}

func TestCheckRefusesPerElement(t *testing.T) {
	exp := renderWeb(t)
	base := live(string(exp))
	cases := map[string][2]string{
		"writeback cache":      {`cache="none"`, `cache="writeback"`},
		"unsafe cache":         {`cache="none"`, `cache="unsafe"`},
		"ignored write errors": {`error_policy="stop"`, `error_policy="ignore"`},
		"ignored read errors":  {`rerror_policy="stop"`, `rerror_policy="ignore"`},
		"threaded io":          {`io="native"`, `io="threads"`},
		"no cache attribute":   {`cache="none" `, ``},
		"disk seclabel":        {`<backingStore/>`, `<backingStore/><seclabel model="dac" relabel="no"/>`},
		"source seclabel":      {`index="1"></source>`, `index="1"><seclabel model="dac" relabel="no"/></source>`},
		"evdev input":          {`<input type="keyboard" bus="ps2"/>`, `<input type="evdev"><source dev="/dev/input/event0"/></input>`},
		"passthrough input":    {`<input type="keyboard" bus="ps2"/>`, `<input type="passthrough" bus="virtio"><source evdev="/dev/input/event1"/></input>`},
		"tablet with a source": {`<input type="tablet" bus="usb"></input>`, `<input type="tablet" bus="usb"><source evdev="/dev/input/event1"/></input>`},
		"channel elsewhere":    {`path="/var/lib/libvirt/qemu/channel/target/domain-7-web/org.qemu.guest_agent.0"`, `path="/etc/shadow"`},
		"channel climbs out":   {`path="/var/lib/libvirt/qemu/channel/target/domain-7-web/org.qemu.guest_agent.0"`, `path="/var/lib/libvirt/qemu/../../../etc/x"`},
		"channel connects":     {`mode="bind"`, `mode="connect"`},
		"vnc socket elsewhere": {`<graphics type="vnc" socket="/var/lib/libvirt/qemu/domain-7-web/vnc.sock">`, `<graphics type="vnc" socket="/root/vnc.sock">`},
		"vnc on a port":        {`<graphics type="vnc" socket="/var/lib/libvirt/qemu/domain-7-web/vnc.sock">`, `<graphics type="vnc" port="5900">`},
		"filter parameter":     {`<filterref filter="clean-traffic"></filterref>`, `<filterref filter="clean-traffic"><parameter name="IP" value="0.0.0.0/0"/></filterref>`},
		"another filter":       {`filter="clean-traffic"`, `filter="allow-all"`},
		"a VLAN":               {`<model type="virtio"></model>`, `<model type="virtio"></model><vlan><tag id="666"/></vlan>`},
		"a ROM file":           {`<model type="virtio"></model>`, `<model type="virtio"></model><rom file="/etc/shadow"/>`},
		"managed tap":          {`<target dev="hv6f1c2a0"></target>`, `<target dev="hv6f1c2a0" managed="no"></target>`},
		"bandwidth":            {`<model type="virtio"></model>`, `<model type="virtio"></model><bandwidth><inbound average="1"/></bandwidth>`},
		"another tap":          {`dev="hv6f1c2a0"`, `dev="vnet9"`},
		"serial to a file":     {`<serial type="pty"><source path="/dev/pts/3"/>`, `<serial type="pty"><source path="/etc/passwd"/>`},
		"serial log":           {`<alias name="serial0"/>`, `<alias name="serial0"/><log file="/etc/cron.d/x"/>`},
		"static label":         {`type="dynamic" model="apparmor" relabel="yes"`, `type="static" model="apparmor" relabel="yes"`},
		"no relabel":           {`type="dynamic" model="apparmor" relabel="yes"`, `type="dynamic" model="apparmor" relabel="no"`},
		"base label":           {`<label>libvirt-x</label>`, `<label>libvirt-x</label><baselabel>unconfined</baselabel>`},
		"selinux label":        {`model="apparmor"`, `model="selinux"`},
		"an extra controller":  {`<controller type="sata" index="0">`, `<controller type="xenbus" index="0">`},
		"usb redirection":      {`</devices>`, `<redirdev bus="usb" type="spicevmc"/></devices>`},
		"a watchdog device":    {`</devices>`, `<watchdog model="i6300esb" action="none"/></devices>`},
		"nvram template":       {`<nvram>`, `<nvram template="/etc/shadow">`},
		"memory backing":       {`<vcpu`, `<memoryBacking><source type="file"/></memoryBacking><vcpu`},
		"trusted rx filters":   {`<interface type="bridge">`, `<interface type="bridge" trustGuestRxFilters="yes">`},
	}
	for name, c := range cases {
		x := strings.Replace(base, c[0], c[1], 1)
		if x == base {
			t.Errorf("%s: the test didn't change anything", name)
			continue
		}
		if err := CheckMigrationXML([]byte(x), exp); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Removing a rendered device is refused too.
	noRNG := strings.Replace(base, `<rng model="virtio">`, `<rngx model="virtio">`, 1)
	noRNG = strings.Replace(noRNG, `</rng>`, `</rngx>`, 1)
	if err := CheckMigrationXML([]byte(noRNG), exp); err == nil {
		t.Error("a missing random number device was accepted")
	}
}
