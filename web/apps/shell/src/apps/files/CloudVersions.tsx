import type { FileBackupVersion, FileEntry } from "@hardy/api-client";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, errorMessage, unwrap } from "../../api";
import { dateTime, relativeTime } from "../../format";
import { CloudUpIcon } from "../../icons";
import { Button } from "../../ui";
import { RestoreDialog } from "../backup/Restore";
import { JobProgress } from "../backup/parts";
import "../backup/backup.css";
import { toast } from "../../ui/toasts";

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
  const [job, setJob] = useState<string | null>(null);
  const list = q.data?.versions ?? [];
  if (q.isError || (q.isSuccess && list.length === 0)) return null;
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
              {canWrite && (
                <div className="fm-version__actions">
                  <Button size="sm" onClick={() => setPick(v)} aria-label={`Restore from the backup of ${dateTime(v.time)}`} disabled={!!job}>
                    Restore
                  </Button>
                </div>
              )}
            </li>
          ))}
        </ul>
      )}
      {job && (
        <JobProgress
          id={job}
          label={`Restoring ${entry.name}`}
          onDone={(j) => {
            void qc.invalidateQueries({ queryKey: ["files", "list", share] });
            if (j.state === "succeeded") toast("success", "Restored from the backup", entry.name);
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
              const r = await unwrap(
                api.POST("/files/backups/restore", {
                  body: { share, target: pick.target, snapshot: pick.snapshot, paths: [entry.path], mode, folder: mode === "copy" ? folder : undefined },
                }),
              );
              setJob(r.job.id);
            } catch (e) {
              throw new Error(errorMessage(e));
            }
          }}
        />
      )}
    </section>
  );
}
