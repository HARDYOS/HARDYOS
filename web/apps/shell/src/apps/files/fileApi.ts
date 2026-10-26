import { CSRF_HEADER, type FileEntry, type FileUpload, type Job } from "@hardy/api-client";
import { useQuery } from "@tanstack/react-query";
import { ApiFailure, api, unwrap } from "../../api";

// The File Manager's side of the files API (docs/plans/file-sharing.md
// section 3, owned by part C) and of share links.

export const useFileShares = () =>
  useQuery({ queryKey: ["files", "shares"], queryFn: () => unwrap(api.GET("/files/shares")).then((r) => r.shares), staleTime: 30_000 });

export const listingKey = (share: string, path: string) => ["files", "list", share, path] as const;

export const useListing = (share: string | null, path: string) =>
  useQuery({
    queryKey: listingKey(share ?? "", path),
    queryFn: () => unwrap(api.GET("/files/list", { params: { query: { share: share!, path } } })).then((r) => r.entries),
    enabled: !!share,
  });

export const useVersions = (share: string, path: string) =>
  useQuery({
    queryKey: ["files", "versions", share, path],
    queryFn: () => unwrap(api.GET("/files/snapshots", { params: { query: { share, path } } })).then((r) => r.versions),
  });

export const useShareLinks = (scope: "mine" | "all") =>
  useQuery({ queryKey: ["sharelinks", scope], queryFn: () => unwrap(api.GET("/sharelinks", { params: { query: { scope } } })).then((r) => r.links) });

/** Waits for a job to finish; throws its error if it fails. */
export async function waitJob(job: Job, onProgress?: (j: Job) => void): Promise<Job> {
  for (;;) {
    const j = await unwrap(api.GET("/jobs/{id}", { params: { path: { id: job.id } } }));
    onProgress?.(j);
    if (j.state === "succeeded") return j;
    if (j.state === "failed" || j.state === "cancelled") throw new Error(j.error || `${j.title}: ${j.state}`);
    await new Promise((r) => setTimeout(r, 600));
  }
}

/** Small operations answer straight away; big ones come back as a job to follow. */
async function maybeJob<T extends object>(data: T | { job: Job }, onProgress?: (j: Job) => void): Promise<T | Job> {
  if (data && "job" in data && data.job) return waitJob(data.job, onProgress);
  return data as T;
}

export const mkdir = (share: string, path: string) => unwrap(api.POST("/files/mkdir", { body: { share, path } }));
export const rename = (share: string, path: string, name: string) => unwrap(api.POST("/files/rename", { body: { share, path, name } }));

export async function transfer(op: "move" | "copy", share: string, paths: string[], toShare: string, toDir: string, onProgress?: (j: Job) => void) {
  const body = { share, paths, toShare, toDir };
  const data = await unwrap(op === "move" ? api.POST("/files/move", { body }) : api.POST("/files/copy", { body }));
  return maybeJob(data as object, onProgress);
}

/** Deletes; true when the items went to the recycle bin. */
export async function remove(share: string, paths: string[], onProgress?: (j: Job) => void): Promise<boolean> {
  const data = await unwrap(api.POST("/files/delete", { body: { share, paths } }));
  const out = await maybeJob(data as object, onProgress);
  if ("recycled" in out) return Boolean((out as { recycled: boolean }).recycled);
  const result = (out as Job).result as { recycled?: boolean } | undefined;
  return Boolean(result?.recycled);
}

export const restore = (share: string, path: string, snapshot: string) =>
  unwrap(api.POST("/files/restore", { body: { share, path, snapshot } })).then((r) => r.path);

/** Size of each upload chunk: big enough to be quick, small enough to retry cheaply. */
export const CHUNK = 8 * 1024 * 1024;

export interface UploadOpts {
  overwrite?: boolean;
  signal?: AbortSignal;
  onProgress?: (sent: number, total: number) => void;
  chunkSize?: number;
}

async function failure(res: Response): Promise<ApiFailure> {
  const e = (await res.json().catch(() => ({}))) as { code?: string; message?: string };
  return new ApiFailure(res.status, e.code ?? "error", e.message ?? res.statusText);
}

/**
 * Uploads one file in chunks: start an upload, PUT each chunk at its offset
 * (retrying a failed chunk up to 3 times, resuming from what the server says
 * it has), and cancel it on the server when the signal aborts.
 */
export async function uploadFile(file: File, share: string, path: string, opts: UploadOpts = {}): Promise<FileEntry | undefined> {
  const chunk = opts.chunkSize ?? CHUNK;
  const start = await unwrap(api.POST("/files/upload", { body: { share, path, size: file.size, overwrite: opts.overwrite ?? false } }));
  const id = start.id;
  const cancel = () =>
    void fetch(`/api/v1/files/upload/${encodeURIComponent(id)}`, { method: "DELETE", headers: { [CSRF_HEADER]: "1" }, credentials: "same-origin" }).catch(
      () => undefined,
    );
  let offset = start.received ?? 0;
  let last: FileUpload = start;
  let tries = 0;
  opts.onProgress?.(offset, file.size);
  try {
    // An empty file still sends one (empty) chunk so the server puts it in place.
    while (offset < file.size || (file.size === 0 && last.received === 0 && !last.entry)) {
      if (opts.signal?.aborted) throw new DOMException("Upload cancelled", "AbortError");
      const end = Math.min(file.size, offset + chunk);
      let res: Response;
      try {
        res = await fetch(`/api/v1/files/upload/${encodeURIComponent(id)}?offset=${offset}`, {
          method: "PUT",
          body: file.slice(offset, end),
          headers: { [CSRF_HEADER]: "1", "Content-Type": "application/octet-stream" },
          credentials: "same-origin",
          signal: opts.signal,
        });
      } catch (err) {
        if (opts.signal?.aborted || (err instanceof DOMException && err.name === "AbortError")) throw err;
        if (++tries > 3) throw new ApiFailure(0, "network", "The connection dropped during the upload.");
        await new Promise((r) => setTimeout(r, 500 * tries));
        continue;
      }
      if (res.status === 409) {
        // Out of step: carry on from what the server has.
        const got = (await res.json().catch(() => ({}))) as Partial<FileUpload>;
        if (typeof got.received === "number" && ++tries <= 3) {
          offset = got.received;
          continue;
        }
        throw new ApiFailure(409, "conflict", "The upload got out of step. Try again.");
      }
      if (res.status >= 500 && ++tries <= 3) {
        await new Promise((r) => setTimeout(r, 500 * tries));
        continue;
      }
      if (!res.ok) throw await failure(res);
      last = (await res.json()) as FileUpload;
      tries = 0;
      offset = last.received ?? end;
      opts.onProgress?.(offset, file.size);
      if (file.size === 0) break;
    }
    return last.entry;
  } catch (err) {
    cancel();
    throw err;
  }
}
