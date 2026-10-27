import type { FileBackupVersion, FileEntry } from "@hardy/api-client";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, errorMessage, unwrap } from "../../api";
import { dateTime, relativeTime } from "../../format";
import { CloudUpIcon } from "../../icons";
import { Button } from "../../ui";
import { Dialog } from "../../ui/Dialog";
import { toast } from "../../ui/toasts";
import { FolderBrowser, RestoreDialog } from "../backup/Restore";
import { JobProgress } from "../backup/parts";
import "../backup/backup.css";

/**
 * "Previous versions" from cloud backups: every version of this shared
 * folder the person may open. Restoring runs as the person (hardyd-priv
 * reads the version and writes the folder with their own permissions).
 */
export function CloudVersions({ share, entry, canWrite }: { share: string; entry: FileEntry; canWrite: boolean }) {
  const q = useQuery({
    queryKey: ["files", "cloud-versions", share],
    queryFn: () => unwrap(api.GET("/files/backups", { params: { query: { share } } })),
    staleTime: 60_000,
    retry: false,
  });
  const qc = useQueryClient();
  const [pick, setPick] = useState<FileBackupVersion | null>(null);
  const [browsing, setBrowsing] = useState<FileBackupVersion | null>(null);
  const [job, setJob] = useState<{ id: string; label: string } | null>(null);
  const list = q.data?.versions ?? [];
  if (q.isError || (q.isSuccess && list.length === 0)) return null;

  const restoreFiles = (v: FileBackupVersion) => async (paths: string[], mode: "copy" | "in_place", folder: string) =>
    unwrap(api.POST("/files/backups/restore", { body: { share, target: v.target, snapshot: v.snapshot, paths, mode, folder: mode === "copy" ? folder : undefined } }));

  return (
    <section className="fm-cloud" aria-label="Versions in cloud backups">
      <h3 className="fm-cloud__title">
        <CloudUpIcon size={15} /> In cloud backups
      </h3>
      {q.isPending ? (
        <p className="small muted">Looking…</p>
      ) : (
        <ul className="fm-versions">
          {list.slice(0, 30).map((v) => (
            <li key={`${v.target}/${v.snapshot}`} className="fm-version">
              <div className="fm-version__text">
                <strong title={dateTime(v.time)}>{relativeTime(v.time)}</strong>
                <span className="small muted">
                  {v.targetName} · {dateTime(v.time)}
                </span>
              </div>
              <div className="fm-version__actions">
                <Button size="sm" onClick={() => setBrowsing(v)} aria-label={`Browse the backup of ${dateTime(v.time)}`}>
                  Browse
                </Button>
                {canWrite && (
                  <Button size="sm" onClick={() => setPick(v)} aria-label={`Restore ${entry.name} from the backup of ${dateTime(v.time)}`} disabled={!!job}>
                    Restore
                  </Button>
                )}
              </div>
            </li>
          ))}
        </ul>
      )}
      {job && (
        <JobProgress
          id={job.id}
          label={job.label}
          onDone={(j) => {
            void qc.invalidateQueries({ queryKey: ["files", "list", share] });
            if (j.state === "succeeded") toast("success", "Restored from the backup", job.label);
            setTimeout(() => setJob(null), 4000);
          }}
        />
      )}
      {pick && (
        <RestoreDialog
          count={1}
          onClose={() => setPick(null)}
          onRestore={async (mode, folder) => {
            try {
              const r = await restoreFiles(pick)([entry.path], mode, folder);
              setJob({ id: r.job.id, label: `Restoring ${entry.name}` });
            } catch (e) {
              throw new Error(errorMessage(e));
            }
          }}
        />
      )}
      {browsing && (
        <Dialog title={`Backup of ${dateTime(browsing.time)}`} width={720} onClose={() => setBrowsing(null)}>
          <FolderBrowser
            target={browsing.target}
            snapshot={browsing.snapshot}
            share={canWrite}
            name="This folder"
            browse={(path) => useFileBrowse(share, browsing, path)}
            submit={restoreFiles(browsing)}
            onJob={(j) => {
              setJob(j);
              setBrowsing(null);
            }}
          />
        </Dialog>
      )}
    </section>
  );
}

/** A folder of a version, listed as the person. */
function useFileBrowse(share: string, v: FileBackupVersion, path: string) {
  return useQuery({
    queryKey: ["files", "cloud-browse", share, v.target, v.snapshot, path],
    queryFn: () => unwrap(api.GET("/files/backups/browse", { params: { query: { share, target: v.target, snapshot: v.snapshot, path } } })),
    staleTime: 60_000,
  });
}
