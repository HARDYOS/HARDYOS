# Game streaming (phase 9, build contract)

Cade's choice (2026-11-21): Sunshine game streaming runs **inside** a Windows
11 gaming VM with a passed-through GPU; HardyOS sets it up; Moonlight plays it
on the home network and over NetBird. Builds on the VM engine and VM polish
(unattended Windows, the `<pool>/vm-catalog` store, `RegisterFirstLogonHook`,
devices only after the install). Decisions 400-409, migration 0120. No new
listener on the host; Sunshine's streaming ports are registered in
`internal/ports` because they're forwarded on the host's NetBird address.

## 1. Wizard

The gaming template gets `streaming: true`. With **Install by itself** on, the
wizard shows **Set up game streaming** (on by default). The request carries
`streaming: {sunshine: true}` and a `streaming` disc; root fills in the rest.
The Network step requires the first card on the home network (bridged) with
the anti-spoofing filter on. GPUs come from the existing Devices step and join
after the install (decision 413).

## 2. First-logon hook and the streaming disc

- Two pinned catalog files (`Kind: file`, never offered as VM disks):
  Sunshine `v2026.914.233613` (`Sunshine-Windows-{AMD64,ARM64}-installer.msi`,
  LizardByte's official installer) and the Virtual Display Driver `25.7.23`
  (`VirtualDisplayDriver-{x86,ARM64}.Driver.Only.zip`), by URL and SHA-256.
  The hashes are GitHub's asset digests, cross-checked against the winget
  manifests; the sandbox this was built in can't reach GitHub's release
  downloads, so a CI job downloads both through the catalog's own client and
  checks them.
- The create job fetches both into `<pool>/vm-catalog` (`vms.catalog.fetch`).
- Root makes a per-VM disc `HARDYOS_STREAM` at
  `/run/hardyos-unattend/<uuid>-stream.iso` (tmpfs, QEMU-owned 0600, built in a
  0700 staging folder like the answer disc): `setup.ps1` (HardyOS's script,
  values from patterns only), the two downloads (grafted from the store after
  their `.verified` record is checked), the Sunshine account
  (`sunshine-account.json`) and a key and certificate root made for this VM's
  Sunshine.
- The `sunshine` first-logon hook runs `setup.ps1` from the drive with that
  label, after the VirtIO guest tools. The script re-checks both SHA-256s,
  installs the MSI silently, writes `sunshine.conf`, sets the account with
  `sunshine.exe --creds`, and installs the driver with SetupAPI (root device
  `Root\MttVDD`), trusting its signer only for the install. No download in the
  guest. The disc goes with the answer disc when the install ends.

## 3. Sunshine account and pairing

- hardyd makes the password (24 letters/digits) inside the create job, seals
  it (secretbox purpose `vm-streaming`, bound to the VM name) into
  `vm_streaming` before the VM exists, and sends it to root only in the
  `vms.create` call. Never in job parameters, logs or vm.json.
- **Reveal** asks the admin's own password again (rate-limited, audited).
- **Safest path to Sunshine's API**: hardyd calls
  `https://<vm address>:47990` itself. The address is root's: the server's ARP
  table entry for the VM's MAC on the bridge's subnet (not the guest's word;
  the card's anti-spoofing filter is on). TLS pins the certificate root made
  (fingerprint in vm.json): nothing else on the LAN can pose as Sunshine, and
  the password is sent only after the pin matches. Rejected: the guest agent
  (`guest-exec` would be a generic command channel into the guest) and root
  making the calls (more root code talking to a guest-controlled service).
- **Pair a device**: the panel lists Sunshine's waiting pairings
  (`GET /api/pin`); the admin enters the PIN Moonlight shows; a job posts
  `{pairing_id, pin, name}` (PIN kept in jobSecrets). Unpair posts
  `/api/clients/unpair`.

## 4. Networking

- Home network: the VM is bridged; Moonlight finds it directly.
- NetBird: `vms.streaming.publish {id, enabled}` (a job). Root forwards TCP
  47984, 47989, 48010 and UDP 47998-48000, 48002, 48010 arriving on the NetBird
  interface from the NetBird network for the server's NetBird address to the
  VM (nft table `ip hardyos_streaming`: DNAT, masquerade; iptables chain
  `HARDYOS-STREAM` because Docker's FORWARD policy drops). 47990 is never
  forwarded. Rules exist only while the VM runs, is published and NetBird is
  connected; resynced every 30 s and on stop/delete. One VM at a time.

## 5. UI

Streaming panel on the VM's overview: Sunshine reachable, home and NetBird
addresses, NetBird toggle with the forwarded ports, pair (PIN dialog) and
unpair, the Sunshine account with Reveal, and driver guidance (NVIDIA/AMD
drivers are the person's; no vGPU unlock, no licence workarounds). GPU VMs
HardyOS didn't set up keep the by-hand steps.

## Review fixes (first security review)

- NetBird forwarding only from devices the admin chooses (none by default,
  never NetBird's proxy, which the app gateway recognises by its valid
  service value); NetBird's policies don't cover DNATed traffic in kernel
  mode (decision 404, 149 amended, remote-access.md). A real NetBird client
  in CI isn't feasible (it needs a management server with signal, relay and
  an identity provider); namespaces test the rules, including a second,
  unchosen peer.
- Pairing: only with exactly one waiting device, the one shown; devices that
  came through NetBird (Sunshine sees the server's bridge address because of
  masquerade) need a confirmation. Sunshine's error text is clipped.
- VM address: exactly one REACHABLE neighbour, agreeing with the guest, MAC
  only on the VM's tap port (bridge fdb).
- Setup: script hash in the first-logon command, exactly one labelled
  volume, labelled library ISOs refused; VDD signer thumbprint pinned (CI
  checks it) with marker and next-boot task to drop the trust; key ACL
  before writing; Windows Firewall rule for 47990 (server only);
  `origin_pin_allowed` not used (unverified in the pinned version).
- Rules removed when hardyd-priv stops and restored if removed while
  running.

## Tests

Go: catalog pins, setup script content (no downloads, hashes, labels), disc
command and contents, validation, create/update/install-end lifecycle, cert,
nft and iptables rendering and refusal of bad values, forwarding sync (ARP
verification, one VM, NetBird down, stop), Sunshine client against a fake TLS
Sunshine (pinning: no password to a wrong certificate), sealed store, API
authz/reveal/pair/unpair/publish/delete. vitest: wizard and panel. CI job
`streaming`: downloads the pinned files and checks SHA-256; loads the rules
into network namespaces and streams TCP/UDP through them; builds a disc with
xorriso. **CI can't run Windows**: the setup script's behaviour inside
Windows (MSI, `--creds`, SetupAPI driver install) is untested in CI.
