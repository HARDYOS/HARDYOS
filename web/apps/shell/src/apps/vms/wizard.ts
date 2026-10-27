import type { VMCapabilities, VMCreateRequest, VMDevice, VMLibraryFile, VMNIC, VMTemplate } from "@hardy/api-client";

/** The New VM wizard's steps, in order. */
export const STEPS = [
  { id: "template", label: "Template" },
  { id: "resources", label: "Name & size" },
  { id: "disks", label: "Disks" },
  { id: "media", label: "Install" },
  { id: "network", label: "Network" },
  { id: "devices", label: "Devices" },
  { id: "review", label: "Review" },
] as const;
export type StepId = (typeof STEPS)[number]["id"];

export type Source = "library" | "url";

export interface WizardDisk {
  name: string;
  sizeGB: number;
  bus: "virtio-scsi" | "virtio-blk" | "sata";
}

export interface WizardNIC {
  mode: VMNIC["mode"];
  vlan: number;
}

export interface WizardState {
  templateId: string;
  name: string;
  id: string;
  /** The person typed their own short name. */
  idTouched: boolean;
  preset: string;
  cores: number;
  threads: number;
  memoryMB: number;
  pool: string;
  disks: WizardDisk[];
  /** Installer disc (iso templates) or disk image (image/cloud templates). */
  source: Source;
  file: string;
  url: string;
  sha256: string;
  virtio: boolean;
  user: string;
  sshKeys: string;
  password: string;
  hostname: string;
  nics: WizardNIC[];
  nicModel: "virtio" | "e1000e";
  devices: VMDevice[];
  firmware: "uefi" | "bios";
  secureBoot: boolean;
  tpm: boolean;
  start: boolean;
  autostart: boolean;
}

/** A short name from a display name: "Dad's Windows" -> "dads-windows". */
export function idFromName(name: string): string {
  let id = name
    .toLowerCase()
    .normalize("NFKD")
    .replace(/[̀-ͯ]/g, "")
    .replace(/['’]/g, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .replace(/-{2,}/g, "-");
  if (id && !/^[a-z]/.test(id)) id = `vm-${id}`;
  id = id.slice(0, 32).replace(/-+$/, "");
  return id.length >= 2 ? id : "";
}

const RESERVED = new Set(["isos", "templates", "capabilities", "bridge", "kept", "new"]);

export function idProblem(id: string, taken: string[]): string | null {
  if (!/^[a-z][a-z0-9-]{0,30}[a-z0-9]$/.test(id) || id.includes("--") || id.includes("-kept-")) {
    return "2 to 32 lowercase letters, digits and dashes, starting with a letter";
  }
  if (RESERVED.has(id)) return "HardyOS keeps that word for itself";
  if (taken.includes(id)) return "There's already a VM with that name";
  return null;
}

/** The file a download is saved as (the server does the same). */
export function fileFromURL(url: string): string {
  try {
    const u = new URL(url.trim());
    let name = decodeURIComponent(u.pathname.split("/").pop() ?? "");
    const lower = name.toLowerCase();
    if (lower.endsWith(".gz")) name = name.slice(0, -3);
    else if (lower.endsWith(".bz2")) name = name.slice(0, -4);
    return name;
  } catch {
    return "";
  }
}

export const isISO = (name: string) => name.toLowerCase().endsWith(".iso");
export const isImage = (name: string) => /\.(qcow2|img|raw|vmdk|vdi|vhdx)(\.xz)?$/i.test(name);

/** Whether the template boots an installer (true) or starts from a disk image. */
export const installsFromISO = (t: VMTemplate) => t.install === "iso";

export function initialState(t: VMTemplate, caps?: VMCapabilities, arch = "x86_64"): WizardState {
  const preset = t.presets.find((p) => p.id === t.defaultPreset) ?? t.presets[0]!;
  const suggested = (t.images ?? []).find((i) => i.urls?.[arch]);
  return {
    templateId: t.id,
    name: "",
    id: "",
    idTouched: false,
    preset: preset.id,
    cores: preset.cores,
    threads: preset.threads,
    memoryMB: preset.memoryMB,
    pool: caps?.library || caps?.pools[0] || "",
    disks: [{ name: "disk0", sizeGB: preset.diskGB, bus: t.diskBus as WizardDisk["bus"] }],
    source: suggested && !installsFromISO(t) ? "url" : "library",
    file: "",
    url: suggested && !installsFromISO(t) ? (suggested.urls?.[arch] ?? "") : "",
    sha256: "",
    virtio: t.virtio,
    user: t.cloudInit ? "admin" : "",
    sshKeys: "",
    password: "",
    hostname: "",
    nics: Array.from({ length: Math.max(1, t.nics) }, () => ({ mode: "bridge" as const, vlan: 0 })),
    nicModel: t.nicModel as WizardState["nicModel"],
    devices: [],
    firmware: t.firmware.type as WizardState["firmware"],
    secureBoot: t.firmware.secureBoot,
    tpm: t.firmware.tpm,
    start: true,
    autostart: t.group === "appliance",
  };
}

export function applyPreset(s: WizardState, t: VMTemplate, presetId: string): WizardState {
  const p = t.presets.find((x) => x.id === presetId);
  if (!p) return { ...s, preset: "custom" };
  // The first disk follows the preset unless the person changed its size.
  const old = t.presets.find((x) => x.id === s.preset);
  const disks = s.disks.map((d, i) => (i === 0 && (!old || d.sizeGB === old.diskGB) ? { ...d, sizeGB: p.diskGB } : d));
  return { ...s, preset: p.id, cores: p.cores, threads: p.threads, memoryMB: p.memoryMB, disks };
}

/** The file the install step names (library pick or download). */
export function chosenFile(s: WizardState): string {
  return s.source === "url" ? fileFromURL(s.url) : s.file;
}

export interface StepContext {
  template?: VMTemplate;
  caps?: VMCapabilities;
  taken: string[];
  library: VMLibraryFile[];
}

/** What stops the person from going on from a step. */
export function stepProblems(s: WizardState, step: StepId, c: StepContext): string[] {
  const p: string[] = [];
  const t = c.template;
  switch (step) {
    case "template":
      if (!t) p.push("Choose what kind of VM to make");
      break;
    case "resources": {
      if (!s.name.trim()) p.push("Give the VM a name");
      const idp = idProblem(s.id, c.taken);
      if (s.name.trim() && idp) p.push(`Short name: ${idp}`);
      if (s.cores < 1) p.push("At least one CPU core");
      if (c.caps && c.caps.cpus > 0 && s.cores * s.threads > c.caps.cpus) p.push(`The server has ${c.caps.cpus} CPU threads`);
      if (t && s.memoryMB < t.minMemoryMB) p.push(`${t.name} needs at least ${Math.round(t.minMemoryMB / 1024)} GB of memory`);
      if (c.caps && c.caps.memoryMB > 0 && s.memoryMB > c.caps.memoryMB) p.push("That's more memory than the server has");
      break;
    }
    case "disks":
      if (!s.pool) p.push("Choose a pool for the disks");
      if (s.disks.length === 0) p.push("Add a disk");
      s.disks.forEach((d, i) => {
        if (!(d.sizeGB >= 1)) p.push(`Disk ${i + 1} needs a size`);
      });
      if (t && (s.disks[0]?.sizeGB ?? 0) < t.minDiskGB) p.push(`${t.name} needs a disk of at least ${t.minDiskGB} GB`);
      break;
    case "media": {
      const f = chosenFile(s);
      const iso = t ? installsFromISO(t) : true;
      if (s.source === "url") {
        if (!/^https:\/\//.test(s.url.trim())) p.push("The link must start with https://");
        else if (!f || !(iso ? isISO(f) : isImage(f))) p.push(iso ? "The link must end in an .iso file" : "The link must end in a disk image (.qcow2, .img, .raw, .vmdk…)");
        if (s.sha256 && !/^[0-9a-fA-F]{64}$/.test(s.sha256.trim())) p.push("The checksum must be 64 hexadecimal characters");
      } else if (!s.file) {
        p.push(iso ? "Choose an installer disc" : "Choose a disk image");
      }
      if (t?.cloudInit) {
        if (!/^[a-z_][a-z0-9_-]{0,30}$/.test(s.user) || s.user === "root") p.push("Choose a user name (lowercase, not root)");
        const keys = sshKeyList(s.sshKeys);
        if (keys.length === 0 && s.password.length === 0) p.push("Add an SSH key or a password to sign in with");
        if (s.password && s.password.length < 8) p.push("The password needs at least 8 characters");
        if (keys.some((k) => !/^(ssh-|ecdsa-|sk-)/.test(k))) p.push("Each SSH key starts with ssh-ed25519, ssh-rsa or ecdsa-");
      }
      break;
    }
    case "network":
      s.nics.forEach((n, i) => {
        if (n.mode === "vlan" && !(n.vlan >= 1 && n.vlan <= 4094)) p.push(`Network card ${i + 1}: the VLAN is 1 to 4094`);
      });
      break;
  }
  return p;
}

export function sshKeyList(text: string): string[] {
  return text
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l !== "");
}

/** The create request the wizard sends. */
export function toRequest(s: WizardState, t: VMTemplate): VMCreateRequest {
  const iso = installsFromISO(t);
  const file = chosenFile(s);
  const media: VMCreateRequest["spec"]["media"] = [];
  if (iso && file) media.push({ kind: "iso", iso: file });
  if (s.virtio) media.push({ kind: "virtio" });
  if (t.cloudInit) media.push({ kind: "cloudinit" });
  const disks = s.disks.map((d, i) => ({
    name: d.name,
    sizeGB: d.sizeGB,
    bus: d.bus,
    ...(i === 0 && !iso && file ? { import: { file } } : {}),
  }));
  const req: VMCreateRequest = {
    spec: {
      id: s.id,
      name: s.name.trim(),
      template: t.id,
      os: t.os,
      pool: s.pool,
      cpu: { cores: s.cores, threads: s.threads as 1 | 2 },
      memory: { mb: s.memoryMB, balloon: t.balloon && s.devices.length === 0 },
      firmware: { type: s.firmware, secureBoot: s.firmware === "uefi" && s.secureBoot, tpm: s.tpm },
      disks,
      media,
      nics: s.nics.map((n) => ({ mode: n.mode, model: s.nicModel, ...(n.mode === "vlan" ? { vlan: n.vlan } : {}) })),
      video: t.video as VMCreateRequest["spec"]["video"],
      guestAgent: true,
      boot: iso ? ["cdrom", "disk"] : ["disk"],
      autostart: { enabled: s.autostart, order: 0, delaySec: 0 },
      devices: s.devices,
    },
    start: s.start,
  };
  if (t.cloudInit) {
    req.spec.cloudInit = { user: s.user, sshKeys: sshKeyList(s.sshKeys), installAgent: true, ...(s.hostname ? { hostname: s.hostname } : {}) };
    if (s.password) req.password = s.password;
  }
  if (s.source === "url" && s.url.trim()) {
    req.downloads = [{ url: s.url.trim(), ...(s.sha256.trim() ? { sha256: s.sha256.trim().toLowerCase() } : {}) }];
  }
  return req;
}
