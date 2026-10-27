import type { FileEntry, OfficeStatus } from "@hardy/api-client";
import { useQuery } from "@tanstack/react-query";
import { api, unwrap } from "../../api";

// The office suite (docs/office.md): its state, and opening and making
// documents. Documents open in an editor window (OFFICE_WINDOW) whose page
// comes from the office origin, never the desktop's.

/** Editor windows have this id prefix plus ":" and the file's share and path. */
export const OFFICE_WINDOW = "os.hardy.office";

export const officeKey = ["office"] as const;

export const useOffice = () =>
  useQuery({ queryKey: officeKey, queryFn: () => unwrap(api.GET("/office")), staleTime: 30_000, retry: false });

export function extOf(name: string): string {
  const i = name.lastIndexOf(".");
  return i > 0 ? name.slice(i + 1).toLowerCase() : "";
}

/** Whether a file opens in the editor right now. */
export function opensInEditor(status: OfficeStatus | undefined, e: Pick<FileEntry, "name" | "dir">): boolean {
  if (!status?.enabled || !status.ready || e.dir) return false;
  const ext = extOf(e.name);
  return status.formats.some((f) => f.ext === ext);
}

/** Whether the editor can save this kind of file (else it opens read only). */
export function editableFormat(status: OfficeStatus | undefined, name: string): boolean {
  const ext = extOf(name);
  return !!status?.formats.some((f) => f.ext === ext && f.editable);
}

/** The window id of a document's editor: one window per file. */
export const editorWindowId = (share: string, path: string) => `${OFFICE_WINDOW}:${share}:${path}`;

export const openDocument = (share: string, path: string, mode: "edit" | "view" = "edit") =>
  unwrap(api.POST("/office/open", { body: { share, path, mode } }));

export const newDocument = (share: string, dir: string, kind: "document" | "spreadsheet" | "presentation", name: string) =>
  unwrap(api.POST("/office/new", { body: { share, dir, kind, name } }));

export const NEW_KINDS = [
  { kind: "document", label: "Document", ext: "docx", fallback: "New document" },
  { kind: "spreadsheet", label: "Spreadsheet", ext: "xlsx", fallback: "New spreadsheet" },
  { kind: "presentation", label: "Presentation", ext: "pptx", fallback: "New presentation" },
] as const;

export type NewKind = (typeof NEW_KINDS)[number]["kind"];
