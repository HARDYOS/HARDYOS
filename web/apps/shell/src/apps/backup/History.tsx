import { bytes, dateTime, duration } from "../../format";
import { ErrorBox, Loading, PageHeader } from "../../ui";
import { useOverview, useRuns } from "./backupApi";
import { RunBadge } from "./parts";
import type { BackupTabProps } from "./tabs";

const kindText: Record<string, string> = { backup: "Backup", restore: "Restore", prune: "Free space", check: "Check", rebuild: "Rebuild" };

export function History(_: BackupTabProps) {
  const runs = useRuns();
  const ov = useOverview();
  if (runs.isPending) return <Loading />;
  if (runs.isError) return <ErrorBox error={runs.error} onRetry={() => runs.refetch()} />;
  const taskName = (id: string) => ov.data?.tasks.find((t) => t.id === id)?.name ?? "";
  const targetName = (id: string) => ov.data?.targets.find((t) => t.id === id)?.name ?? id;
  return (
    <div className="stack">
      <PageHeader title="History" subtitle="Backups, restores and upkeep, newest first." />
      {runs.data.runs.length === 0 ? (
        <p className="muted small">Nothing has run yet.</p>
      ) : (
        <div className="bk-table-wrap">
          <table className="bk-table">
            <thead>
              <tr>
                <th scope="col">When</th>
                <th scope="col">What</th>
                <th scope="col">Where</th>
                <th scope="col">Result</th>
                <th scope="col" className="num">
                  Size
                </th>
                <th scope="col" className="num">
                  New
                </th>
                <th scope="col" className="num">
                  Took
                </th>
              </tr>
            </thead>
            <tbody>
              {runs.data.runs.map((r) => {
                const took = r.finishedAt ? (new Date(r.finishedAt).getTime() - new Date(r.startedAt).getTime()) / 1000 : null;
                return (
                  <tr key={r.id}>
                    <td className="small">{dateTime(r.startedAt)}</td>
                    <td>
                      <strong>{kindText[r.kind] ?? r.kind}</strong>
                      {r.taskId && <span className="small muted"> · {taskName(r.taskId)}</span>}
                    </td>
                    <td className="small">{targetName(r.target)}</td>
                    <td>
                      <RunBadge run={r} />
                      {r.error && (
                        <div className="small muted bk-err" title={r.error}>
                          {r.error}
                        </div>
                      )}
                    </td>
                    <td className="num mono small">{r.bytes ? bytes(r.bytes) : "—"}</td>
                    <td className="num mono small">{r.added ? bytes(r.added) : "—"}</td>
                    <td className="num mono small">{took !== null && r.state !== "missed" ? duration(took) : "—"}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
