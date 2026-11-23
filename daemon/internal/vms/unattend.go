package vms

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf16"

	"github.com/hardyos/hardyos/daemon/internal/rootfile"
)

// Unattended Windows installs (decision 412). The person brings their own
// Windows ISO (HardyOS handles no licences or product keys); root writes
// an answer file (autounattend.xml) onto a small disc of its own that
// Windows Setup finds by itself. The account's password is only ever on
// that disc (QEMU's own file, 0600, like the cloud-init seed), never in
// vm.json; taking the disc out of the VM deletes it.
//
// What the answer file does: wipes and partitions the VM's first disk (a
// new VM's empty disk: the answer disc is only made when a VM is created),
// loads the VirtIO storage and network drivers from the drivers disc,
// installs the chosen edition, names the computer, sets the language,
// keyboard and time zone, makes the local administrator account, signs it
// in once, and at that first sign-in installs the VirtIO guest tools and
// runs every first-logon hook the VM asks for.

// Unattend is a VM's unattended install settings.
type Unattend struct {
	// User is the local administrator account Setup makes.
	User string `json:"user"`
	// ComputerName is Windows' computer name (default: the VM's name).
	ComputerName string `json:"computerName,omitempty"`
	// Locale is the language and formats (en-US); Keyboard the input
	// locale (default the same, or a layout like 0409:00000409).
	Locale   string `json:"locale"`
	Keyboard string `json:"keyboard,omitempty"`
	// TimeZone is a Windows time zone name ("W. Europe Standard Time").
	TimeZone string `json:"timeZone,omitempty"`
	// Edition is the image to install by name ("Windows 11 Pro"), or
	// ImageIndex its number in install.wim; neither: the first image.
	Edition    string `json:"edition,omitempty"`
	ImageIndex int    `json:"imageIndex,omitempty"`
	// Hooks are first-logon steps registered with RegisterFirstLogonHook.
	Hooks []string `json:"hooks,omitempty"`
	// Pending: Windows isn't installed yet. Until it is, the VM gets none
	// of its passed-through devices and no USB hot-plug, so Setup only
	// ever sees (and wipes) the VM's own new disks. It ends when the guest
	// agent (installed at first logon) answers, or when the person takes
	// the answer disc out.
	Pending bool `json:"pending"`
	// Started: the first start happened and root answered the installer
	// disc's "press any key".
	Started bool `json:"started,omitempty"`
}

// InstallPending reports a Windows install that isn't finished.
func (s *Spec) InstallPending() bool {
	return s.Unattend != nil && s.Unattend.Pending && s.HasUnattendMedia()
}

// LogonCommand is one first-logon step.
type LogonCommand struct {
	Description string
	CommandLine string
}

// HookVM is what a first-logon hook may know about the VM: values that
// passed their patterns (VM name: lowercase letters, digits, dashes;
// user: letters, digits, . _ -; arch: amd64 or arm64), never free text.
// A hook still quotes them: no command line may interpolate a value
// unquoted.
type HookVM struct {
	ID   string
	User string
	Arch string
}

// FirstLogonHook gives the commands of a named first-logon step for a VM.
// Hooks are Go code (never data from hardyd), so what runs inside a
// person's Windows is always something HardyOS ships.
type FirstLogonHook func(vm HookVM) []LogonCommand

var (
	hooksMu         sync.RWMutex
	firstLogonHooks = map[string]FirstLogonHook{}
	hookNameRE      = regexp.MustCompile(`^[a-z][a-z0-9-]{1,31}$`)
)

// RegisterFirstLogonHook adds a first-logon step that a VM's unattended
// install can name (Unattend.Hooks). It panics on a bad or reused name:
// hooks are registered from init functions.
func RegisterFirstLogonHook(name string, h FirstLogonHook) {
	hooksMu.Lock()
	defer hooksMu.Unlock()
	if !hookNameRE.MatchString(name) || h == nil {
		panic("vms: bad first-logon hook name " + name)
	}
	if _, dup := firstLogonHooks[name]; dup {
		panic("vms: first-logon hook registered twice: " + name)
	}
	firstLogonHooks[name] = h
}

// FirstLogonHooks lists the registered hooks' names.
func FirstLogonHooks() []string {
	hooksMu.RLock()
	defer hooksMu.RUnlock()
	out := make([]string, 0, len(firstLogonHooks))
	for n := range firstLogonHooks {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func firstLogonHook(name string) (FirstLogonHook, bool) {
	hooksMu.RLock()
	defer hooksMu.RUnlock()
	h, ok := firstLogonHooks[name]
	return h, ok
}

// UnattendRunDir holds answer discs (<vm uuid>.iso): in /run, so the
// password is in no dataset, snapshot, replica or backup, and gone with
// the next boot of the server (decision 412).
const UnattendRunDir = "/run/hardyos-unattend"

func unattendPath(s *Spec) string { return filepath.Join(UnattendRunDir, s.UUID+".iso") }

var (
	winUserRE     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,19}$`)
	winComputerRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,14}$`)
	localeRE      = regexp.MustCompile(`^[a-z]{2,3}(-[A-Za-z0-9]{2,8}){0,2}$`)
	keyboardRE    = regexp.MustCompile(`^([a-z]{2,3}(-[A-Za-z0-9]{2,8}){0,2}|[0-9a-fA-F]{4}:[0-9a-fA-F]{8})$`)
	timeZoneRE    = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9 .()+-]{0,63}$`)
	editionRE     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ()._-]{0,79}$`)
)

// reservedWinUsers are accounts Windows has already.
var reservedWinUsers = []string{"administrator", "guest", "defaultaccount", "wdagutilityaccount", "system", "none"}

// MaxHooks bounds the first-logon hooks of one VM.
const MaxHooks = 8

func (u *Unattend) normalize(s *Spec) {
	u.User = strings.TrimSpace(u.User)
	u.ComputerName = strings.TrimSpace(u.ComputerName)
	u.Locale = strings.TrimSpace(u.Locale)
	u.Keyboard = strings.TrimSpace(u.Keyboard)
	u.TimeZone = strings.TrimSpace(u.TimeZone)
	u.Edition = strings.TrimSpace(u.Edition)
	if u.Locale == "" {
		u.Locale = "en-US"
	}
	if u.ComputerName == "" {
		n := strings.ToUpper(s.ID)
		if len(n) > 15 {
			n = strings.TrimRight(n[:15], "-")
		}
		u.ComputerName = n
	}
}

// problems checks the settings (Validate).
func (u *Unattend) problems(s *Spec) []string {
	var p []string
	if s.OS != "windows" {
		p = append(p, "an unattended install is for Windows VMs")
	}
	if !winUserRE.MatchString(u.User) || slices.Contains(reservedWinUsers, strings.ToLower(u.User)) {
		p = append(p, fmt.Sprintf("the Windows user name %q isn't valid (up to 20 letters, digits, . _ -; not Administrator or Guest)", u.User))
	}
	if !winComputerRE.MatchString(u.ComputerName) || strings.Trim(u.ComputerName, "0123456789") == "" {
		p = append(p, fmt.Sprintf("the computer name %q isn't valid (up to 15 letters, digits and dashes, not only digits)", u.ComputerName))
	}
	if !localeRE.MatchString(u.Locale) {
		p = append(p, fmt.Sprintf("%q isn't a language tag like en-US", u.Locale))
	}
	if u.Keyboard != "" && !keyboardRE.MatchString(u.Keyboard) {
		p = append(p, fmt.Sprintf("%q isn't a keyboard like en-US or 0409:00000409", u.Keyboard))
	}
	if u.TimeZone != "" && !timeZoneRE.MatchString(u.TimeZone) {
		p = append(p, fmt.Sprintf("%q isn't a Windows time zone name", u.TimeZone))
	}
	if u.Edition != "" && !editionRE.MatchString(u.Edition) {
		p = append(p, fmt.Sprintf("%q isn't a Windows edition name", u.Edition))
	}
	if u.ImageIndex < 0 || u.ImageIndex > 64 || (u.ImageIndex > 0 && u.Edition != "") {
		p = append(p, "choose the edition by name or by number, not both (number 1 to 64)")
	}
	if len(u.Hooks) > MaxHooks {
		p = append(p, fmt.Sprintf("at most %d first-logon steps", MaxHooks))
	}
	seen := map[string]bool{}
	for _, h := range u.Hooks {
		if _, ok := firstLogonHook(h); !ok || seen[h] {
			p = append(p, fmt.Sprintf("%q isn't a first-logon step HardyOS has (or is listed twice)", h))
		}
		seen[h] = true
	}
	if !s.HasUnattendMedia() {
		p = append(p, "an unattended install needs its answer disc (media kind unattend)")
	}
	return p
}

// createProblems is what a new VM with an unattended install also needs.
func (u *Unattend) createProblems(s *Spec) []string {
	var p []string
	if len(s.Files()) == 0 {
		p = append(p, "an unattended install needs the Windows installer disc")
	}
	for _, d := range s.Disks {
		if d.Import != nil || d.Clone != nil {
			p = append(p, "an unattended install wipes the first disk, so it can't go with an imported image or a template's disk")
			break
		}
	}
	if len(s.Disks) == 0 {
		p = append(p, "an unattended install needs a disk to install onto")
	}
	return p
}

// winArch is Windows' name for the architecture.
func winArch(arch string) string {
	if arch == "aarch64" {
		return "arm64"
	}
	return "amd64"
}

// driverDir is the VirtIO disc's folder name for the Windows version.
func driverDir(template string) string {
	switch template {
	case "windows-server-2025":
		return "2k25"
	case "windows10":
		return "w10"
	default:
		return "w11"
	}
}

// encodePassword is the answer file's "not plain text" form of a password
// (base64 of UTF-16LE password+suffix): it only keeps the password from a
// glance, it isn't encryption.
func encodePassword(pw, suffix string) string {
	u := utf16.Encode([]rune(pw + suffix))
	b := make([]byte, 0, 2*len(u))
	for _, c := range u {
		b = append(b, byte(c), byte(c>>8))
	}
	return base64.StdEncoding.EncodeToString(b)
}

func esc(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// GuestToolsCommand installs the VirtIO guest tools (network, display,
// balloon, guest agent) from the drive whose volume label is the drivers
// disc's, never from whatever drive happens to have a file of that name.
const GuestToolsCommand = `powershell -NoProfile -ExecutionPolicy Bypass -Command "$v = Get-Volume | Where-Object { $_.DriveType -eq 'CD-ROM' -and $_.FileSystemLabel -like 'virtio-win*' } | Select-Object -First 1; if ($v) { Start-Process -Wait -FilePath ($v.DriveLetter + ':\virtio-win-guest-tools.exe') -ArgumentList '/install','/quiet','/norestart' }"`

// AnswerFile builds autounattend.xml for a VM. password is the account's.
func AnswerFile(s *Spec, arch, password string) ([]byte, error) {
	u := s.Unattend
	if u == nil {
		return nil, fmt.Errorf("%s has no unattended install settings", s.ID)
	}
	if len(password) < 8 || len(password) > 127 || strings.ContainsAny(password, "\x00\r\n") {
		return nil, Problems{"the Windows password must be 8 to 127 characters on one line"}
	}
	wa := winArch(arch)
	comp := func(name string) string {
		return fmt.Sprintf(`<component name="%s" processorArchitecture="%s" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">`, name, wa)
	}
	kb := u.Keyboard
	if kb == "" {
		kb = u.Locale
	}
	uefi := s.Firmware.Type == FirmwareUEFI
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format, a...); b.WriteByte('\n') }
	w(`<?xml version="1.0" encoding="utf-8"?>`)
	w(`<!-- Made by HardyOS for the VM %s. It holds the account's password: HardyOS deletes this disc when it's taken out of the VM. -->`, esc(s.ID))
	w(`<unattend xmlns="urn:schemas-microsoft-com:unattend">`)

	// windowsPE: language, drivers, disk, image.
	w(`<settings pass="windowsPE">`)
	w("%s", comp("Microsoft-Windows-International-Core-WinPE"))
	w(`<SetupUILanguage><UILanguage>%s</UILanguage></SetupUILanguage>`, esc(u.Locale))
	w(`<InputLocale>%s</InputLocale><SystemLocale>%s</SystemLocale><UILanguage>%s</UILanguage><UserLocale>%s</UserLocale>`, esc(kb), esc(u.Locale), esc(u.Locale), esc(u.Locale))
	w(`</component>`)
	if s.NeedsVirtio() {
		w("%s", comp("Microsoft-Windows-PnpCustomizationsWinPE"))
		w(`<DriverPaths>`)
		n := 1
		dir := driverDir(s.Template)
		for _, letter := range []string{"D", "E", "F", "G", "H"} {
			for _, drv := range []string{"vioscsi", "viostor", "NetKVM"} {
				w(`<PathAndCredentials wcm:action="add" wcm:keyValue="%d"><Path>%s:\%s\%s\%s</Path></PathAndCredentials>`, n, letter, drv, dir, wa)
				n++
			}
		}
		w(`</DriverPaths>`)
		w(`</component>`)
	}
	w("%s", comp("Microsoft-Windows-Setup"))
	w(`<DiskConfiguration><Disk wcm:action="add"><DiskID>0</DiskID><WillWipeDisk>true</WillWipeDisk><CreatePartitions>`)
	if uefi {
		w(`<CreatePartition wcm:action="add"><Order>1</Order><Type>EFI</Type><Size>260</Size></CreatePartition>`)
		w(`<CreatePartition wcm:action="add"><Order>2</Order><Type>MSR</Type><Size>16</Size></CreatePartition>`)
		w(`<CreatePartition wcm:action="add"><Order>3</Order><Type>Primary</Type><Extend>true</Extend></CreatePartition>`)
		w(`</CreatePartitions><ModifyPartitions>`)
		w(`<ModifyPartition wcm:action="add"><Order>1</Order><PartitionID>1</PartitionID><Format>FAT32</Format><Label>System</Label></ModifyPartition>`)
		w(`<ModifyPartition wcm:action="add"><Order>2</Order><PartitionID>2</PartitionID></ModifyPartition>`)
		w(`<ModifyPartition wcm:action="add"><Order>3</Order><PartitionID>3</PartitionID><Format>NTFS</Format><Label>Windows</Label><Letter>C</Letter></ModifyPartition>`)
	} else {
		w(`<CreatePartition wcm:action="add"><Order>1</Order><Type>Primary</Type><Size>500</Size></CreatePartition>`)
		w(`<CreatePartition wcm:action="add"><Order>2</Order><Type>Primary</Type><Extend>true</Extend></CreatePartition>`)
		w(`</CreatePartitions><ModifyPartitions>`)
		w(`<ModifyPartition wcm:action="add"><Order>1</Order><PartitionID>1</PartitionID><Format>NTFS</Format><Label>System</Label><Active>true</Active></ModifyPartition>`)
		w(`<ModifyPartition wcm:action="add"><Order>2</Order><PartitionID>2</PartitionID><Format>NTFS</Format><Label>Windows</Label><Letter>C</Letter></ModifyPartition>`)
	}
	w(`</ModifyPartitions></Disk></DiskConfiguration>`)
	part := 3
	if !uefi {
		part = 2
	}
	w(`<ImageInstall><OSImage>`)
	switch {
	case u.Edition != "":
		w(`<InstallFrom><MetaData wcm:action="add"><Key>/IMAGE/NAME</Key><Value>%s</Value></MetaData></InstallFrom>`, esc(u.Edition))
	case u.ImageIndex > 0:
		w(`<InstallFrom><MetaData wcm:action="add"><Key>/IMAGE/INDEX</Key><Value>%d</Value></MetaData></InstallFrom>`, u.ImageIndex)
	}
	w(`<InstallTo><DiskID>0</DiskID><PartitionID>%d</PartitionID></InstallTo>`, part)
	w(`</OSImage></ImageInstall>`)
	// No product key: Windows stays unactivated until the person
	// activates it with their own licence.
	w(`<UserData><AcceptEula>true</AcceptEula></UserData>`)
	w(`</component>`)
	w(`</settings>`)

	// specialize: the computer's name and time zone.
	w(`<settings pass="specialize">`)
	w("%s", comp("Microsoft-Windows-Shell-Setup"))
	w(`<ComputerName>%s</ComputerName>`, esc(u.ComputerName))
	if u.TimeZone != "" {
		w(`<TimeZone>%s</TimeZone>`, esc(u.TimeZone))
	}
	w(`</component>`)
	w(`</settings>`)

	// oobeSystem: the account, one automatic sign-in, first-logon steps.
	w(`<settings pass="oobeSystem">`)
	w("%s", comp("Microsoft-Windows-International-Core"))
	w(`<InputLocale>%s</InputLocale><SystemLocale>%s</SystemLocale><UILanguage>%s</UILanguage><UserLocale>%s</UserLocale>`, esc(kb), esc(u.Locale), esc(u.Locale), esc(u.Locale))
	w(`</component>`)
	w("%s", comp("Microsoft-Windows-Shell-Setup"))
	w(`<OOBE><HideEULAPage>true</HideEULAPage><HideOEMRegistrationScreen>true</HideOEMRegistrationScreen><HideOnlineAccountScreens>true</HideOnlineAccountScreens><HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE><ProtectYourPC>3</ProtectYourPC></OOBE>`)
	w(`<UserAccounts><LocalAccounts><LocalAccount wcm:action="add"><Name>%s</Name><DisplayName>%s</DisplayName><Group>Administrators</Group><Password><Value>%s</Value><PlainText>false</PlainText></Password></LocalAccount></LocalAccounts></UserAccounts>`,
		esc(u.User), esc(u.User), encodePassword(password, "Password"))
	w(`<AutoLogon><Enabled>true</Enabled><LogonCount>1</LogonCount><Username>%s</Username><Password><Value>%s</Value><PlainText>false</PlainText></Password></AutoLogon>`,
		esc(u.User), encodePassword(password, "Password"))
	cmds := firstLogonCommands(s, arch)
	if len(cmds) > 0 {
		w(`<FirstLogonCommands>`)
		for i, c := range cmds {
			w(`<SynchronousCommand wcm:action="add"><Order>%d</Order><CommandLine>%s</CommandLine><Description>%s</Description></SynchronousCommand>`, i+1, esc(c.CommandLine), esc(c.Description))
		}
		w(`</FirstLogonCommands>`)
	}
	w(`</component>`)
	w(`</settings>`)
	w(`</unattend>`)
	out := []byte(b.String())
	var root struct{ XMLName xml.Name }
	if err := xml.Unmarshal(out, &root); err != nil || root.XMLName.Local != "unattend" {
		return nil, fmt.Errorf("the answer file isn't valid XML: %v", err)
	}
	return out, nil
}

// firstLogonCommands are the steps run at the first sign-in, in order.
func firstLogonCommands(s *Spec, arch string) []LogonCommand {
	u := s.Unattend
	cmds := []LogonCommand{{
		Description: "The account's password doesn't expire",
		CommandLine: fmt.Sprintf(`powershell -NoProfile -Command "Set-LocalUser -Name '%s' -PasswordNeverExpires $true"`, u.User),
	}}
	if s.NeedsVirtio() {
		cmds = append(cmds, LogonCommand{Description: "VirtIO guest tools (drivers and the QEMU guest agent)", CommandLine: GuestToolsCommand})
	}
	hv := HookVM{ID: s.ID, User: u.User, Arch: winArch(arch)}
	for _, name := range u.Hooks {
		if h, ok := firstLogonHook(name); ok {
			for _, c := range h(hv) {
				if c.CommandLine != "" && !strings.ContainsAny(c.CommandLine, "\x00\r\n") && len(c.CommandLine) <= 1024 {
					cmds = append(cmds, c)
				}
			}
		}
	}
	return cmds
}

// unattendDir makes sure /run/hardyos-unattend is root's own folder (0711:
// QEMU reaches its own disc by name, nobody can list them).
func (m *Manager) unattendDir() (string, error) {
	dir := m.sys(UnattendRunDir)
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		return "", err
	}
	if err := os.Mkdir(dir, 0o711); err != nil && !os.IsExist(err) {
		return "", err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return "", err
	}
	if !fi.IsDir() {
		return "", fmt.Errorf("%s isn't a folder", UnattendRunDir)
	}
	if sys, ok := fi.Sys().(*syscall.Stat_t); ok && rootfile.Enforce && sys.Uid != 0 {
		return "", fmt.Errorf("%s isn't root's", UnattendRunDir)
	}
	if err := os.Chmod(dir, 0o711); err != nil {
		return "", err
	}
	return dir, nil
}

// writeUnattend makes the VM's answer disc. Everything is made in a 0700
// folder, so neither the answer file nor the disc is readable by anyone
// else at any moment, and the disc is QEMU's own (0600) before it's put in
// place.
func (m *Manager) writeUnattend(ctx context.Context, st *stored, password string) error {
	xmlb, err := AnswerFile(&st.spec, m.arch().Arch, password)
	if err != nil {
		return err
	}
	dir, err := m.unattendDir()
	if err != nil {
		return err
	}
	stage, err := os.MkdirTemp(dir, ".stage-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	if err := os.Chmod(stage, 0o700); err != nil {
		return err
	}
	if err := os.Mkdir(filepath.Join(stage, "in"), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(stage, "in", "autounattend.xml"), xmlb, 0o600); err != nil {
		return err
	}
	rel := filepath.Join(UnattendRunDir, filepath.Base(stage)) // as xorriso sees it
	if _, err := m.run(ctx, "xorriso", "-as", "mkisofs", "-quiet", "-volid", "UNATTEND", "-joliet", "-rock",
		"-output", filepath.Join(rel, "out.iso"), filepath.Join(rel, "in")); err != nil {
		return fmt.Errorf("making the Windows answer disc: %w", err)
	}
	out := filepath.Join(stage, "out.iso")
	if err := m.ownSeed(out); err != nil {
		return err
	}
	return os.Rename(out, m.sys(unattendPath(&st.spec)))
}

// removeUnattend deletes the answer disc (it holds the password).
func (m *Manager) removeUnattend(st *stored) {
	if st.spec.UUID == "" {
		return
	}
	if err := os.Remove(m.sys(unattendPath(&st.spec))); err != nil && !os.IsNotExist(err) {
		m.log().Warn("vms: deleting the Windows answer disc", "id", st.spec.ID, "err", err)
	}
}

// checkUnattendDisc makes sure the answer disc is QEMU's own plain file.
func (m *Manager) checkUnattendDisc(s *Spec) error {
	p := m.sys(unattendPath(s))
	fi, err := os.Lstat(p)
	if err != nil {
		return Problems{"the Windows setup disc is gone (it's kept in memory so the password is never saved, and the server restarted); take it out of the VM in Hardware and finish Windows setup on its screen, or make the VM again"}
	}
	if !fi.Mode().IsRegular() {
		return errors.New("the Windows setup disc isn't a file")
	}
	if sys, ok := fi.Sys().(*syscall.Stat_t); ok && rootfile.Enforce && (sys.Nlink != 1 || !m.qemuOwned(seedFile, sys.Uid)) {
		return errors.New("the Windows setup disc isn't QEMU's own file")
	}
	return m.ownSeed(p)
}

// HasUnattendMedia reports whether the answer disc is in a drive.
func (s *Spec) HasUnattendMedia() bool {
	for _, m := range s.Media {
		if m.Kind == MediaUnattend {
			return true
		}
	}
	return false
}

// BootKeyPresses is how long root keeps answering the installer disc's
// "Press any key to boot from CD or DVD" on an unattended install's first
// start.
var (
	BootKeyPresses = 12
	BootKeyEvery   = time.Second
)

// answerBootPrompt presses Enter for the installer's boot prompt, in the
// background, on the first start only.
func (m *Manager) answerBootPrompt(st *stored) {
	id := st.spec.ID
	st.spec.Unattend.Started = true
	if err := m.saveSpec(st); err != nil {
		m.log().Warn("vms: saving the VM after starting its unattended install", "id", id, "err", err)
	}
	go func() {
		for i := 0; i < BootKeyPresses; i++ {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			_, err := m.virsh(ctx, "send-key", id, "KEY_ENTER")
			cancel()
			if err != nil {
				return
			}
			time.Sleep(BootKeyEvery)
		}
	}()
}

// checkInstalled ends a running VM's unattended install once its guest
// agent answers (the guest tools that bring it are installed at the first
// sign-in, the last step of Setup): the answer disc comes out of the VM's
// settings and is deleted, and its devices join at the next start.
func (m *Manager) checkInstalled(ctx context.Context, id string) {
	unlock, ok := m.tryLock(id)
	if !ok {
		return
	}
	defer unlock()
	st, err := m.find(ctx, id)
	if err != nil || !st.spec.InstallPending() || !st.spec.Unattend.Started || !st.spec.GuestAgent {
		return
	}
	pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	_, err = m.virsh(pctx, "qemu-agent-command", id, `{"execute":"guest-ping"}`, "--timeout", "5")
	cancel()
	if err != nil {
		return
	}
	s := st.spec
	// The streaming disc goes too: its step ran at the first sign-in
	// (a running QEMU keeps reading the file it has open).
	s.Media, s.Unattend = withoutMedia(withoutMedia(s.Media, MediaUnattend), MediaStreaming), nil
	st.spec = s
	if err := m.saveSpec(st); err != nil {
		m.log().Warn("vms: saving the VM after its Windows install", "id", id, "err", err)
		return
	}
	m.removeUnattend(st)
	m.removeStreaming(st)
	if err := m.define(ctx, st, nil); err != nil {
		m.log().Warn("vms: redefining the VM after its Windows install", "id", id, "err", err)
	}
	if len(s.Devices) > 0 {
		m.statsMu.Lock()
		if m.restart == nil {
			m.restart = map[string]bool{}
		}
		m.restart[id] = true
		m.statsMu.Unlock()
	}
	m.log().Info("vms: Windows is installed; the setup disc is deleted", "id", id)
}
