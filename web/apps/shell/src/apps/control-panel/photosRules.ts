import type { PhotosSettings } from "@hardy/api-client";

/** Plain words for the machine learning mode Immich runs. */
export function mlLabel(mode: string): string {
  switch (mode) {
    case "cuda":
      return "NVIDIA GPU";
    case "openvino":
      return "Intel GPU";
    case "rocm":
      return "AMD GPU";
    default:
      return "Processor";
  }
}

/** The app's existing-photos shares, as the install dialog names them. */
export function shareLabel(name: string): string {
  return name === "EXISTING" ? "Existing photos" : name === "EXISTING_2" ? "More existing photos (2)" : name === "EXISTING_3" ? "More existing photos (3)" : name;
}

/** What's wrong with the libraries before saving (the server checks too). */
export function libraryProblems(s: PhotosSettings): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  s.libraries.forEach((l, i) => {
    const n = `Folder ${i + 1}`;
    if (!l.ownerId) out.push(`${n}: choose whose library it joins`);
    if (!l.name.trim()) out.push(`${n}: give it a name`);
    const p = l.path.trim().replace(/^\.?\/*$/, "");
    if (p.startsWith("/") || p.split("/").includes("..") || p.includes("\\")) out.push(`${n}: write the folder inside the shared folder, like Pictures/2019`);
    const key = `${l.ownerId}:${l.share}:${p.replace(/\/+$/, "")}`;
    if (seen.has(key)) out.push(`${n}: the same folder is already in that person's library`);
    seen.add(key);
  });
  if (s.scanHours < 1 || s.scanHours > 168) out.push("Look for new photos every 1 to 168 hours");
  return out;
}
