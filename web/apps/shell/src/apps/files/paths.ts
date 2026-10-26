import type { FileEntry } from "@hardy/api-client";

/** The share id of the person's own Home folder (files.HomeShare). */
export const HOME = "~home";

/** Joins a folder path inside a share and a name: "" + "a" = "a", "a" + "b" = "a/b". */
export function join(dir: string, name: string): string {
  return dir ? `${dir}/${name}` : name;
}

/** The folder a path is in: "a/b/c" -> "a/b", "a" -> "". */
export function parent(path: string): string {
  const i = path.lastIndexOf("/");
  return i < 0 ? "" : path.slice(0, i);
}

export function basename(path: string): string {
  return path.slice(path.lastIndexOf("/") + 1);
}

/** Breadcrumb trail for a path: [{name, path}] from the top down. */
export function crumbs(path: string): { name: string; path: string }[] {
  if (!path) return [];
  const parts = path.split("/");
  return parts.map((name, i) => ({ name, path: parts.slice(0, i + 1).join("/") }));
}

/** Names HardyOS never shows (the recycle bin, snapshots, its own files). */
export function hidden(name: string): boolean {
  const n = name.toLowerCase();
  return n === ".recycle" || n === ".zfs" || n.startsWith(".hardyos");
}

/** What's wrong with a new file or folder name, or null. */
export function nameProblem(name: string, taken: string[] = []): string | null {
  const n = name.trim();
  if (!n) return "Type a name.";
  if (n === "." || n === "..") return "That name isn't allowed.";
  if (n.includes("/")) return "Names can't contain /.";
  if (n.includes("\0")) return "That name isn't allowed.";
  if (new TextEncoder().encode(n).length > 255) return "That name is too long.";
  if (hidden(n)) return "That name is kept for HardyOS.";
  if (taken.some((t) => t.toLowerCase() === n.toLowerCase())) return "Something with that name is already here.";
  return null;
}

export type Kind = "folder" | "image" | "video" | "audio" | "pdf" | "text" | "archive" | "doc" | "file";

const EXT: Record<string, Kind> = {};
const add = (kind: Kind, exts: string) => exts.split(" ").forEach((e) => (EXT[e] = kind));
add("image", "jpg jpeg png gif webp avif bmp ico heic");
add("video", "mp4 m4v webm mov mkv ogv");
add("audio", "mp3 m4a aac wav flac ogg oga opus");
add("pdf", "pdf");
add("text", "txt md markdown log csv tsv json yaml yml toml ini conf cfg xml html htm css js ts tsx jsx go py sh rs c h cpp java rb php sql srt vtt nfo env");
add("archive", "zip tar gz tgz bz2 xz 7z rar zst iso");
add("doc", "doc docx odt rtf xls xlsx ods ppt pptx odp pages numbers key");

export function kindOf(e: Pick<FileEntry, "name" | "dir">): Kind {
  if (e.dir) return "folder";
  const dot = e.name.lastIndexOf(".");
  if (dot <= 0) return "file";
  return EXT[e.name.slice(dot + 1).toLowerCase()] ?? "file";
}

/** Kinds the quick preview can show. heic and mkv mostly can't play in browsers but are tried. */
export function previewable(e: Pick<FileEntry, "name" | "dir">): boolean {
  const k = kindOf(e);
  return k === "image" || k === "video" || k === "audio" || k === "pdf" || k === "text";
}

export type SortKey = "name" | "size" | "modified" | "kind";
export interface Sort {
  key: SortKey;
  asc: boolean;
}

const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: "base" });

/** Folders first, then by the chosen column; names break ties. */
export function sortEntries(list: FileEntry[], sort: Sort): FileEntry[] {
  const dir = sort.asc ? 1 : -1;
  return [...list].sort((a, b) => {
    if (a.dir !== b.dir) return a.dir ? -1 : 1;
    let c = 0;
    if (sort.key === "size") c = a.size - b.size;
    else if (sort.key === "modified") c = Date.parse(a.modified) - Date.parse(b.modified);
    else if (sort.key === "kind") c = collator.compare(kindOf(a), kindOf(b));
    if (c === 0) c = collator.compare(a.name, b.name);
    return c * dir;
  });
}

/** "photo.jpg" -> "photo (2).jpg" for a name that's taken. */
export function numbered(name: string, n: number): string {
  const dot = name.lastIndexOf(".");
  if (dot <= 0) return `${name} (${n})`;
  return `${name.slice(0, dot)} (${n})${name.slice(dot)}`;
}

/** The download address for files (a zip for folders or several items). */
export function downloadUrl(share: string, paths: string[], opts: { snapshot?: string; inline?: boolean } = {}): string {
  const q = new URLSearchParams({ share });
  for (const p of paths) q.append("path", p);
  if (opts.snapshot) q.set("snapshot", opts.snapshot);
  if (opts.inline) q.set("inline", "1");
  return `/api/v1/files/download?${q.toString()}`;
}
