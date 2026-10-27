package vms

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/hardyos/hardyos/daemon/internal/devices"
)

// XMLNamespace marks domains HardyOS made, in their <metadata>.
const XMLNamespace = "https://hardyos.dev/xmlns/vm/1"

// Paths are the files a domain uses, resolved by the Manager.
type Paths struct {
	// StateDir is the VM dataset's mountpoint (nvram.fd lives there).
	StateDir string
	// ISOs maps an ISO library file name to its path.
	ISOs map[string]string
	// Virtio is the VirtIO drivers disc.
	Virtio string
	// CloudInit is the generated seed disc.
	CloudInit string
	// Bridge is the home network's bridge (br0).
	Bridge string
	// NATNetwork is libvirt's NAT network (default).
	NATNetwork string
}

type domainXML struct {
	XMLName       xml.Name    `xml:"domain"`
	Type          string      `xml:"type,attr"`
	Name          string      `xml:"name"`
	UUID          string      `xml:"uuid"`
	Title         string      `xml:"title,omitempty"`
	Description   string      `xml:"description,omitempty"`
	Metadata      metadataXML `xml:"metadata"`
	Memory        sizeXML     `xml:"memory"`
	CurrentMemory sizeXML     `xml:"currentMemory"`
	VCPU          vcpuXML     `xml:"vcpu"`
	OS            osXML       `xml:"os"`
	Features      featuresXML `xml:"features"`
	CPU           cpuXML      `xml:"cpu"`
	Clock         clockXML    `xml:"clock"`
	OnPoweroff    string      `xml:"on_poweroff"`
	OnReboot      string      `xml:"on_reboot"`
	OnCrash       string      `xml:"on_crash"`
	PM            *pmXML      `xml:"pm"`
	Devices       devicesXML  `xml:"devices"`
}

type metadataXML struct {
	VM metaVM `xml:"hardyos:vm"`
}

type metaVM struct {
	NS       string `xml:"xmlns:hardyos,attr"`
	ID       string `xml:"id,attr"`
	Template string `xml:"template,attr"`
	Pool     string `xml:"pool,attr"`
}

type sizeXML struct {
	Unit  string `xml:"unit,attr"`
	Value int    `xml:",chardata"`
}

type vcpuXML struct {
	Placement string `xml:"placement,attr"`
	Value     int    `xml:",chardata"`
}

type osXML struct {
	Firmware string         `xml:"firmware,attr,omitempty"`
	Type     osTypeXML      `xml:"type"`
	FwFeat   *fwFeaturesXML `xml:"firmware"`
	Loader   *loaderXML     `xml:"loader"`
	NVRAM    string         `xml:"nvram,omitempty"`
	BootMenu *bootMenuXML   `xml:"bootmenu"`
}

type osTypeXML struct {
	Arch    string `xml:"arch,attr"`
	Machine string `xml:"machine,attr"`
	Value   string `xml:",chardata"`
}

type fwFeaturesXML struct {
	Features []fwFeature `xml:"feature"`
}

type fwFeature struct {
	Enabled string `xml:"enabled,attr"`
	Name    string `xml:"name,attr"`
}

type loaderXML struct {
	Secure string `xml:"secure,attr"`
}

type bootMenuXML struct {
	Enable  string `xml:"enable,attr"`
	Timeout int    `xml:"timeout,attr"`
}

type featuresXML struct {
	ACPI   *struct{}  `xml:"acpi"`
	APIC   *struct{}  `xml:"apic"`
	HyperV *hypervXML `xml:"hyperv"`
	VMPort *stateXML  `xml:"vmport"`
	SMM    *stateXML  `xml:"smm"`
}

type stateXML struct {
	State string `xml:"state,attr"`
}

type hypervXML struct {
	Mode        string       `xml:"mode,attr"`
	Relaxed     stateXML     `xml:"relaxed"`
	VAPIC       stateXML     `xml:"vapic"`
	Spinlocks   spinlocksXML `xml:"spinlocks"`
	VPIndex     stateXML     `xml:"vpindex"`
	Runtime     stateXML     `xml:"runtime"`
	Synic       stateXML     `xml:"synic"`
	STimer      stateXML     `xml:"stimer"`
	Frequencies stateXML     `xml:"frequencies"`
	TLBFlush    stateXML     `xml:"tlbflush"`
	IPI         stateXML     `xml:"ipi"`
}

type spinlocksXML struct {
	State   string `xml:"state,attr"`
	Retries int    `xml:"retries,attr"`
}

type cpuXML struct {
	Mode       string      `xml:"mode,attr"`
	Check      string      `xml:"check,attr"`
	Migratable string      `xml:"migratable,attr"`
	Topology   topologyXML `xml:"topology"`
}

type topologyXML struct {
	Sockets int `xml:"sockets,attr"`
	Dies    int `xml:"dies,attr"`
	Cores   int `xml:"cores,attr"`
	Threads int `xml:"threads,attr"`
}

type clockXML struct {
	Offset string     `xml:"offset,attr"`
	Timers []timerXML `xml:"timer"`
}

type timerXML struct {
	Name       string `xml:"name,attr"`
	TickPolicy string `xml:"tickpolicy,attr,omitempty"`
	Present    string `xml:"present,attr,omitempty"`
}

type pmXML struct {
	Mem  stateEnabled `xml:"suspend-to-mem"`
	Disk stateEnabled `xml:"suspend-to-disk"`
}

type stateEnabled struct {
	Enabled string `xml:"enabled,attr"`
}

type devicesXML struct {
	Controllers []controllerXML `xml:"controller"`
	Disks       []diskXML       `xml:"disk"`
	Interfaces  []interfaceXML  `xml:"interface"`
	Channels    []channelXML    `xml:"channel"`
	Inputs      []inputXML      `xml:"input"`
	Graphics    *graphicsXML    `xml:"graphics"`
	Video       *videoXML       `xml:"video"`
	TPM         *tpmXML         `xml:"tpm"`
	Serial      *serialXML      `xml:"serial"`
	Console     *consoleXML     `xml:"console"`
	MemBalloon  memBalloonXML   `xml:"memballoon"`
	RNG         rngXML          `xml:"rng"`
	// Passed-through devices from devices.Manager.Prepare, checked by
	// checkFragment.
	Extra string `xml:",innerxml"`
}

type controllerXML struct {
	Type  string `xml:"type,attr"`
	Index int    `xml:"index,attr"`
	Model string `xml:"model,attr,omitempty"`
	Ports int    `xml:"ports,attr,omitempty"`
}

type diskXML struct {
	Type     string        `xml:"type,attr"`
	Device   string        `xml:"device,attr"`
	Driver   driverXML     `xml:"driver"`
	Source   *diskSource   `xml:"source"`
	Target   targetXML     `xml:"target"`
	ReadOnly *struct{}     `xml:"readonly"`
	Serial   string        `xml:"serial,omitempty"`
	Boot     *bootOrderXML `xml:"boot"`
	Alias    *aliasXML     `xml:"alias"`
}

type driverXML struct {
	Name    string `xml:"name,attr"`
	Type    string `xml:"type,attr"`
	Cache   string `xml:"cache,attr,omitempty"`
	IO      string `xml:"io,attr,omitempty"`
	Discard string `xml:"discard,attr,omitempty"`
}

type diskSource struct {
	Dev      string       `xml:"dev,attr,omitempty"`
	File     string       `xml:"file,attr,omitempty"`
	SecLabel *secLabelXML `xml:"seclabel"`
}

type secLabelXML struct {
	Model   string `xml:"model,attr"`
	Relabel string `xml:"relabel,attr"`
}

type targetXML struct {
	Dev string `xml:"dev,attr"`
	Bus string `xml:"bus,attr"`
}

type bootOrderXML struct {
	Order int `xml:"order,attr"`
}

type aliasXML struct {
	Name string `xml:"name,attr"`
}

type interfaceXML struct {
	Type   string          `xml:"type,attr"`
	MAC    macXML          `xml:"mac"`
	Source ifaceSourceXML  `xml:"source"`
	Target *ifaceTargetXML `xml:"target"`
	Model  modelXML        `xml:"model"`
	Boot   *bootOrderXML   `xml:"boot"`
}

type macXML struct {
	Address string `xml:"address,attr"`
}

type ifaceSourceXML struct {
	Bridge  string `xml:"bridge,attr,omitempty"`
	Network string `xml:"network,attr,omitempty"`
}

type ifaceTargetXML struct {
	Dev string `xml:"dev,attr"`
}

type modelXML struct {
	Type string `xml:"type,attr"`
}

type channelXML struct {
	Type   string           `xml:"type,attr"`
	Target channelTargetXML `xml:"target"`
}

type channelTargetXML struct {
	Type string `xml:"type,attr"`
	Name string `xml:"name,attr"`
}

type inputXML struct {
	Type string `xml:"type,attr"`
	Bus  string `xml:"bus,attr"`
}

type graphicsXML struct {
	Type   string    `xml:"type,attr"`
	Listen listenXML `xml:"listen"`
}

type listenXML struct {
	Type string `xml:"type,attr"`
}

type videoXML struct {
	Model videoModelXML `xml:"model"`
}

type videoModelXML struct {
	Type    string `xml:"type,attr"`
	Heads   int    `xml:"heads,attr,omitempty"`
	Primary string `xml:"primary,attr,omitempty"`
}

type tpmXML struct {
	Model   string        `xml:"model,attr"`
	Backend tpmBackendXML `xml:"backend"`
}

type tpmBackendXML struct {
	Type    string `xml:"type,attr"`
	Version string `xml:"version,attr"`
}

type serialXML struct {
	Type   string        `xml:"type,attr"`
	Target portTargetXML `xml:"target"`
}

type consoleXML struct {
	Type   string        `xml:"type,attr"`
	Target portTargetXML `xml:"target"`
}

type portTargetXML struct {
	Type string `xml:"type,attr,omitempty"`
	Port int    `xml:"port,attr"`
}

type memBalloonXML struct {
	Model    string    `xml:"model,attr"`
	FreePage string    `xml:"freePageReporting,attr,omitempty"`
	Stats    *statsXML `xml:"stats"`
}

type statsXML struct {
	Period int `xml:"period,attr"`
}

type rngXML struct {
	Model   string        `xml:"model,attr"`
	Backend rngBackendXML `xml:"backend"`
}

type rngBackendXML struct {
	Model string `xml:"model,attr"`
	Value string `xml:",chardata"`
}

// diskLetters names targets: sda, sdb… (scsi and sata) or vda… (virtio).
func targetName(prefix string, n int) string {
	if n < 26 {
		return prefix + string(rune('a'+n))
	}
	return fmt.Sprintf("%s%c%c", prefix, rune('a'+n/26-1), rune('a'+n%26))
}

// DomainXML builds libvirt's domain definition for s. s must be normalized
// and valid; devs are the fragments devices.Manager.Prepare returned (nil
// when the VM isn't about to start, e.g. when it's only defined).
func DomainXML(s *Spec, a ArchInfo, p Paths, devs []devices.Prepared) ([]byte, error) {
	if s.UUID == "" {
		return nil, errors.New("the VM has no UUID yet")
	}
	if a.Arch == "" {
		return nil, errors.New("VMs aren't supported on this server's architecture")
	}
	d := domainXML{
		Type: "kvm", Name: s.ID, UUID: s.UUID, Title: s.Name, Description: s.Description,
		Metadata:      metadataXML{VM: metaVM{NS: XMLNamespace, ID: s.ID, Template: s.Template, Pool: s.Pool}},
		Memory:        sizeXML{Unit: "MiB", Value: s.Memory.MB},
		CurrentMemory: sizeXML{Unit: "MiB", Value: s.Memory.MB},
		VCPU:          vcpuXML{Placement: "static", Value: s.CPU.VCPUs()},
		OnPoweroff:    "destroy", OnReboot: "restart", OnCrash: "destroy",
	}
	windows := s.OS == "windows"

	// Firmware: libvirt picks the firmware file from the features asked
	// for, so nothing here names an x86-only path.
	d.OS.Type = osTypeXML{Arch: a.Arch, Machine: a.Machine, Value: "hvm"}
	d.OS.BootMenu = &bootMenuXML{Enable: "yes", Timeout: 3000}
	if s.Firmware.Type == FirmwareUEFI {
		d.OS.Firmware = "efi"
		sb := "no"
		if s.Firmware.SecureBoot {
			sb = "yes"
		}
		d.OS.FwFeat = &fwFeaturesXML{Features: []fwFeature{{Enabled: sb, Name: "enrolled-keys"}, {Enabled: sb, Name: "secure-boot"}}}
		if s.Firmware.SecureBoot {
			d.OS.Loader = &loaderXML{Secure: "yes"}
		}
		if p.StateDir == "" {
			return nil, errors.New("the VM's state folder is unknown")
		}
		d.OS.NVRAM = filepath.Join(p.StateDir, "nvram.fd")
	}

	d.Features.ACPI = &struct{}{}
	if a.Arch == "x86_64" || a.Arch == "i686" {
		d.Features.APIC = &struct{}{}
	}
	if a.VMPort {
		d.Features.VMPort = &stateXML{State: "off"}
	}
	if a.SMM && s.Firmware.SecureBoot {
		d.Features.SMM = &stateXML{State: "on"}
	}
	on := stateXML{State: "on"}
	if windows && a.HyperV {
		d.Features.HyperV = &hypervXML{Mode: "custom", Relaxed: on, VAPIC: on, Spinlocks: spinlocksXML{State: "on", Retries: 8191},
			VPIndex: on, Runtime: on, Synic: on, STimer: on, Frequencies: on, TLBFlush: on, IPI: on}
	}

	d.CPU = cpuXML{Mode: "host-passthrough", Check: "none", Migratable: "on",
		Topology: topologyXML{Sockets: 1, Dies: 1, Cores: s.CPU.Cores, Threads: s.CPU.Threads}}

	d.Clock.Offset = "utc"
	if windows {
		d.Clock.Offset = "localtime"
	}
	if a.PIT {
		d.Clock.Timers = append(d.Clock.Timers, timerXML{Name: "rtc", TickPolicy: "catchup"}, timerXML{Name: "pit", TickPolicy: "delay"}, timerXML{Name: "hpet", Present: "no"})
	}
	if windows && a.HyperV {
		d.Clock.Timers = append(d.Clock.Timers, timerXML{Name: "hypervclock", Present: "yes"})
	}
	if a.Arch == "x86_64" {
		d.PM = &pmXML{Mem: stateEnabled{"no"}, Disk: stateEnabled{"no"}}
	}

	// Boot order: each device carries its own position.
	bootPos := map[string]int{}
	for i, b := range s.Boot {
		bootPos[b] = i + 1
	}
	order := map[string]int{} // next free position per kind (only the first of each kind boots)
	bootFor := func(kind string) *bootOrderXML {
		pos, ok := bootPos[kind]
		if !ok || order[kind] > 0 {
			return nil
		}
		order[kind] = pos
		return &bootOrderXML{Order: pos}
	}

	dv := &d.Devices
	needSCSI := false
	for _, dk := range s.Disks {
		if dk.Bus == BusVirtioSCSI {
			needSCSI = true
		}
	}
	if a.CDBus == "scsi" && len(s.Media) > 0 {
		needSCSI = true
	}
	if needSCSI {
		dv.Controllers = append(dv.Controllers, controllerXML{Type: "scsi", Index: 0, Model: "virtio-scsi"})
	}
	dv.Controllers = append(dv.Controllers, controllerXML{Type: "usb", Index: 0, Model: "qemu-xhci", Ports: 15})

	var scsiN, sataN, vdN int
	nextTarget := func(bus string) targetXML {
		switch bus {
		case BusVirtioBlk:
			t := targetXML{Dev: targetName("vd", vdN), Bus: "virtio"}
			vdN++
			return t
		case BusSATA:
			t := targetXML{Dev: targetName("sd", scsiN+sataN), Bus: "sata"}
			sataN++
			return t
		default:
			t := targetXML{Dev: targetName("sd", scsiN+sataN), Bus: "scsi"}
			scsiN++
			return t
		}
	}
	for _, dk := range s.Disks {
		dv.Disks = append(dv.Disks, diskXML{
			Type: "block", Device: "disk",
			Driver: driverXML{Name: "qemu", Type: "raw", Cache: "none", IO: "native", Discard: "unmap"},
			Source: &diskSource{Dev: ZvolPath(s.Pool, s.ID, dk.Name)},
			Target: nextTarget(dk.Bus),
			Serial: s.ID + "-" + dk.Name,
			Boot:   bootFor("disk"),
		})
	}
	for i, m := range s.Media {
		var src *diskSource
		switch m.Kind {
		case MediaISO:
			path, ok := p.ISOs[m.ISO]
			if !ok {
				return nil, fmt.Errorf("the disc %s isn't in the ISO library", m.ISO)
			}
			src = &diskSource{File: path}
		case MediaVirtio:
			if p.Virtio == "" {
				return nil, errors.New("the VirtIO drivers disc hasn't been downloaded yet")
			}
			src = &diskSource{File: p.Virtio}
		case MediaCloudInit:
			if p.CloudInit == "" {
				return nil, errors.New("the cloud-init disc hasn't been made yet")
			}
			src = &diskSource{File: p.CloudInit}
		}
		if src != nil {
			// QEMU reads discs as itself; libvirt must not take shared
			// folder files over (chown) to let it (decision 122).
			src.SecLabel = &secLabelXML{Model: "dac", Relabel: "no"}
		}
		bus := a.CDBus
		dv.Disks = append(dv.Disks, diskXML{
			Type: "file", Device: "cdrom",
			Driver:   driverXML{Name: "qemu", Type: "raw"},
			Source:   src,
			Target:   nextTarget(bus),
			ReadOnly: &struct{}{},
			Boot:     bootFor("cdrom"),
			Alias:    &aliasXML{Name: fmt.Sprintf("ua-cd%d", i)},
		})
	}
	for i, n := range s.NICs {
		ifc := interfaceXML{MAC: macXML{Address: n.MAC}, Model: modelXML{Type: n.Model}, Boot: bootFor("network")}
		if n.MAC == "" {
			return nil, fmt.Errorf("network card %d has no MAC address yet", i+1)
		}
		switch n.Mode {
		case NICNAT:
			ifc.Type = "network"
			ifc.Source.Network = p.NATNetwork
			if ifc.Source.Network == "" {
				ifc.Source.Network = "default"
			}
		default: // bridge and vlan: the VLAN is set on the port after start
			if p.Bridge == "" {
				return nil, errors.New("the home network's bridge isn't set up yet")
			}
			ifc.Type = "bridge"
			ifc.Source.Bridge = p.Bridge
		}
		ifc.Target = &ifaceTargetXML{Dev: tapName(s.UUID, i)}
		dv.Interfaces = append(dv.Interfaces, ifc)
	}
	if s.GuestAgent {
		dv.Channels = append(dv.Channels, channelXML{Type: "unix", Target: channelTargetXML{Type: "virtio", Name: "org.qemu.guest_agent.0"}})
	}
	dv.Inputs = []inputXML{{Type: "tablet", Bus: "usb"}, {Type: "keyboard", Bus: "usb"}}
	// The console: VNC on a socket only libvirt and root can reach;
	// hardyd-priv hands a connection to hardyd (vms.console.open).
	dv.Graphics = &graphicsXML{Type: "vnc", Listen: listenXML{Type: "socket"}}
	// A GPU that is the main display replaces the emulated one.
	primaryGPU := false
	for _, d := range s.Devices {
		primaryGPU = primaryGPU || d.Primary
	}
	if s.Video != "none" && !primaryGPU {
		dv.Video = &videoXML{Model: videoModelXML{Type: s.Video, Heads: 1, Primary: "yes"}}
	} else {
		dv.Video = &videoXML{Model: videoModelXML{Type: "none"}}
	}
	if s.Firmware.TPM {
		dv.TPM = &tpmXML{Model: a.TPMModel, Backend: tpmBackendXML{Type: "emulator", Version: "2.0"}}
	}
	dv.Serial = &serialXML{Type: "pty", Target: portTargetXML{Port: 0}}
	dv.Console = &consoleXML{Type: "pty", Target: portTargetXML{Type: "serial", Port: 0}}
	if s.Memory.Balloon {
		dv.MemBalloon = memBalloonXML{Model: "virtio", FreePage: "on", Stats: &statsXML{Period: 5}}
	} else {
		dv.MemBalloon = memBalloonXML{Model: "none"}
	}
	dv.RNG = rngXML{Model: "virtio", Backend: rngBackendXML{Model: "random", Value: "/dev/urandom"}}

	var extra strings.Builder
	for _, pd := range devs {
		frag, err := checkFragment(pd.XML)
		if err != nil {
			return nil, fmt.Errorf("device %s: %w", pd.Device.ID, err)
		}
		extra.WriteString(frag)
	}
	dv.Extra = extra.String()

	out, err := xml.MarshalIndent(d, "", "  ")
	if err != nil {
		return nil, err
	}
	out = append(out, '\n')
	// Whatever went in, the result must be one well-formed domain.
	if err := wellFormed(out, "domain"); err != nil {
		return nil, fmt.Errorf("the domain XML isn't valid: %w", err)
	}
	return out, nil
}

// fragmentRoots are the elements a device fragment may be.
var fragmentRoots = map[string]bool{"hostdev": true}

// MaxHostdevs bounds the <hostdev> elements one device brings (a GPU's
// functions).
const MaxHostdevs = 8

// checkFragment accepts a device's XML only when it's one or more
// <hostdev> elements (with whatever inside them; a GPU brings one per
// function), so a fragment can't add emulators, command lines or other
// devices to the domain. It's re-indented to sit inside <devices>.
func checkFragment(frag string) (string, error) {
	dec := xml.NewDecoder(strings.NewReader(frag))
	depth := 0
	roots := 0
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("its XML isn't valid: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if depth == 0 {
				roots++
				if !fragmentRoots[t.Name.Local] || t.Name.Space != "" {
					return "", fmt.Errorf("its XML must be a <hostdev>, not <%s>", t.Name.Local)
				}
			}
			if t.Name.Space != "" {
				return "", errors.New("its XML may not use namespaces")
			}
			for _, at := range t.Attr {
				if at.Name.Space != "" {
					return "", errors.New("its XML may not use namespaced attributes")
				}
			}
			depth++
		case xml.EndElement:
			depth--
		case xml.CharData:
			if depth == 0 && len(bytes.TrimSpace(t)) > 0 {
				return "", errors.New("its XML has text outside the element")
			}
		case xml.ProcInst, xml.Directive:
			return "", errors.New("its XML may not have processing instructions or directives")
		}
	}
	if roots < 1 || roots > MaxHostdevs || depth != 0 {
		return "", fmt.Errorf("its XML must be 1 to %d <hostdev> elements", MaxHostdevs)
	}
	var b strings.Builder
	for _, line := range strings.Split(strings.Trim(frag, "\n"), "\n") {
		if strings.TrimSpace(line) != "" {
			b.WriteString("\n  " + strings.TrimRight(line, " \t\r"))
		}
	}
	return b.String(), nil
}

func wellFormed(b []byte, root string) error {
	dec := xml.NewDecoder(bytes.NewReader(b))
	depth, roots := 0, 0
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if depth == 0 {
				roots++
				if t.Name.Local != root {
					return fmt.Errorf("the root is <%s>", t.Name.Local)
				}
			}
			depth++
		case xml.EndElement:
			depth--
		case xml.Directive, xml.ProcInst:
			return errors.New("directives aren't allowed")
		}
	}
	if roots != 1 {
		return errors.New("more than one root element")
	}
	return nil
}
