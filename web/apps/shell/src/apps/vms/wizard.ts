import type { VMCapabilities, VMCreateRequest, VMDevice, VMLibraryFile, VMNIC, VMTemplate, VMUserTemplate } from "@hardy/api-client";

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

/** Where the install comes from: the ISO library, a link, the verified catalog or a saved template. */
export type Source = "library" | "url" | "catalog" | "template";

export interface WizardDisk {
  name: string;
  sizeGB: number;
  bus: "virtio-scsi" | "virtio-blk" | "sata";
}

export interface WizardNIC {
  mode: VMNIC["mode"];
  vlan: number;
  /** Let the card use other computers' addresses (routers); off by default. */
  allowSpoofing: boolean;
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
  /** Make the VM even if its thin disks are bigger than the pool's free space. */
  allowOvercommit: boolean;
  /** The verified image (catalog) the template starts from, "" for none. */
  catalog: string;
  /** Windows installs by itself (answer file); user and password are the account's. */
  unattend: boolean;
  edition: string;
  locale: string;
  timeZone: string;
  sound: boolean;
  clipboard: boolean;
  /** The saved template the VM is copied from (source "template"). */
  userTemplate: string;
  /** Media of the saved template (drivers and cloud-init discs). */
  templateMedia: ("virtio" | "cloudinit")[];
  /** The saved template's disks (copied; other disks start empty). */
  templateDisks: string[];
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

const RESERVED = new Set(["isos", "templates", "catalog", "usertemplates", "capabilities", "bridge", "kept", "new"]);

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

/** The browser's language as a Windows locale, when it looks like one. */
export function browserLocale(): string {
  const l = typeof navigator !== "undefined" ? navigator.language : "";
  return /^[a-z]{2,3}-[A-Z]{2}$/.test(l) ? l : "en-US";
}

export const LOCALE_RE = /^[a-z]{2,3}(-[A-Za-z0-9]{2,8}){0,2}$/;
export const WIN_USER_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,19}$/;
const WIN_RESERVED = new Set(["administrator", "guest", "defaultaccount", "wdagutilityaccount", "system", "none"]);

export function initialState(t: VMTemplate, caps?: VMCapabilities, arch = "x86_64"): WizardState {
  const preset = t.presets.find((p) => p.id === t.defaultPreset) ?? t.presets[0]!;
  const suggested = (t.images ?? []).find((i) => i.urls?.[arch]);
  const catalog = t.catalog ?? "";
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
    source: catalog ? "catalog" : suggested && !installsFromISO(t) ? "url" : "library",
    file: "",
    url: suggested && !installsFromISO(t) ? (suggested.urls?.[arch] ?? "") : "",
    sha256: "",
    virtio: t.virtio,
    user: t.cloudInit ? "admin" : "",
    sshKeys: "",
    password: "",
    hostname: "",
    nics: Array.from({ length: Math.max(1, t.nics) }, () => ({ mode: "bridge" as const, vlan: 0, allowSpoofing: t.allowSpoofing })),
    nicModel: t.nicModel as WizardState["nicModel"],
    devices: [],
    firmware: t.firmware.type as WizardState["firmware"],
    secureBoot: t.firmware.secureBoot,
    tpm: t.firmware.tpm,
    start: true,
    allowOvercommit: false,
    autostart: t.group === "appliance",
    catalog,
    unattend: !!t.unattend,
    edition: t.editions?.[0] ?? "",
    locale: browserLocale(),
    timeZone: "",
    sound: !!t.sound,
    clipboard: !!t.clipboard,
    userTemplate: "",
    templateMedia: [],
    templateDisks: [],
  };
}

/** A new VM from a saved template: its built-in template's choices, the saved sizes, disks copied. */
export function fromUserTemplate(ut: VMUserTemplate, base: VMTemplate, caps?: VMCapabilities, arch = "x86_64"): WizardState {
  const s = initialState(base, caps, arch);
  const sp = ut.spec;
  return {
    ...s,
    preset: "custom",
    cores: sp.cpu.cores,
    threads: sp.cpu.threads,
    memoryMB: sp.memory.mb,
    pool: ut.pool,
    disks: sp.disks.map((d) => ({ name: d.name, sizeGB: d.sizeGB, bus: d.bus })),
    source: "template",
    catalog: "",
    unattend: false,
    nics: sp.nics.map((n) => ({ mode: n.mode, vlan: n.vlan ?? 0, allowSpoofing: !!n.allowSpoofing })),
    nicModel: (sp.nics[0]?.model ?? s.nicModel) as WizardState["nicModel"],
    firmware: sp.firmware.type,
    secureBoot: sp.firmware.secureBoot,
    tpm: sp.firmware.tpm,
    user: sp.cloudInit?.user ?? s.user,
    sshKeys: (sp.cloudInit?.sshKeys ?? []).join("\n"),
    virtio: false,
    sound: !!sp.sound,
    clipboard: !!sp.clipboard,
    userTemplate: ut.id,
    templateMedia: sp.media.filter((m) => m.kind === "virtio" || m.kind === "cloudinit").map((m) => m.kind as "virtio" | "cloudinit"),
    templateDisks: sp.disks.map((d) => d.name),
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
  if (s.source === "catalog" || s.source === "template") return "";
  return s.source === "url" ? fileFromURL(s.url) : s.file;
}

/** Whether the VM gets cloud-init settings. */
export const usesCloudInit = (s: WizardState, t: VMTemplate) => (s.source === "template" ? s.templateMedia.includes("cloudinit") : t.cloudInit);

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
      if (s.source === "template" && s.templateDisks.some((n) => !s.disks.some((d) => d.name === n))) p.push("Keep the template's disks: they're copied into the new VM");
      break;
    case "media": {
      const f = chosenFile(s);
      const iso = t ? installsFromISO(t) : true;
      if (s.source === "catalog" || s.source === "template") {
        // Nothing to choose: a verified image, or the template's disks.
      } else if (s.source === "url") {
        if (!/^https:\/\//.test(s.url.trim())) p.push("The link must start with https://");
        else if (!f || !(iso ? isISO(f) : isImage(f))) p.push(iso ? "The link must end in an .iso file" : "The link must end in a disk image (.qcow2, .img, .raw, .vmdk…)");
        if (s.sha256 && !/^[0-9a-fA-F]{64}$/.test(s.sha256.trim())) p.push("The checksum must be 64 hexadecimal characters");
      } else if (!s.file) {
        p.push(iso ? "Choose an installer disc" : "Choose a disk image");
      }
      if (t && s.unattend && t.unattend && s.source !== "template") {
        if (!WIN_USER_RE.test(s.user) || WIN_RESERVED.has(s.user.toLowerCase())) p.push("Choose a Windows user name (not Administrator or Guest)");
        if (s.password.length < 8) p.push("The Windows account needs a password of at least 8 characters");
        if (!LOCALE_RE.test(s.locale)) p.push("The language must look like en-US");
      }
      if (t && usesCloudInit(s, t)) {
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
  const fromTemplate = s.source === "template" && s.userTemplate !== "";
  const iso = installsFromISO(t) && !fromTemplate;
  const file = chosenFile(s);
  const cloudInit = usesCloudInit(s, t);
  const unattend = iso && s.unattend && !!t.unattend;
  const media: VMCreateRequest["spec"]["media"] = [];
  if (iso && file) media.push({ kind: "iso", iso: file });
  if (s.virtio || unattend || (fromTemplate && s.templateMedia.includes("virtio"))) media.push({ kind: "virtio" });
  if (cloudInit) media.push({ kind: "cloudinit" });
  if (unattend) media.push({ kind: "unattend" });
  const disks = s.disks.map((d, i) => ({
    name: d.name,
    sizeGB: d.sizeGB,
    bus: d.bus,
    ...(i === 0 && !iso && file && !fromTemplate ? { import: { file } } : {}),
    ...(fromTemplate && s.templateDisks.includes(d.name) ? { clone: { template: s.userTemplate } } : {}),
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
      nics: s.nics.map((n) => ({
        mode: n.mode,
        model: s.nicModel,
        ...(n.mode === "vlan" ? { vlan: n.vlan } : {}),
        ...(n.mode !== "nat" && n.allowSpoofing ? { allowSpoofing: true } : {}),
      })),
      video: t.video as VMCreateRequest["spec"]["video"],
      guestAgent: true,
      boot: iso ? ["cdrom", "disk"] : ["disk"],
      autostart: { enabled: s.autostart, order: 0, delaySec: 0 },
      devices: s.devices,
      ...(s.sound ? { sound: true } : {}),
      ...(s.clipboard ? { clipboard: true } : {}),
      ...(fromTemplate ? { fromTemplate: s.userTemplate } : {}),
    },
    start: s.start,
    ...(s.allowOvercommit ? { allowOvercommit: true } : {}),
  };
  if (s.source === "catalog" && s.catalog && !fromTemplate) req.catalog = s.catalog;
  if (unattend) {
    req.spec.unattend = {
      user: s.user,
      locale: s.locale,
      pending: true,
      ...(s.timeZone.trim() ? { timeZone: s.timeZone.trim() } : {}),
      ...(s.edition.trim() ? { edition: s.edition.trim() } : {}),
    };
    req.password = s.password;
  }
  if (cloudInit) {
    req.spec.cloudInit = { user: s.user, sshKeys: sshKeyList(s.sshKeys), installAgent: true, ...(s.hostname ? { hostname: s.hostname } : {}) };
    if (s.password) req.password = s.password;
  }
  if (s.source === "url" && s.url.trim()) {
    req.downloads = [{ url: s.url.trim(), ...(s.sha256.trim() ? { sha256: s.sha256.trim().toLowerCase() } : {}) }];
  }
  return req;
}
