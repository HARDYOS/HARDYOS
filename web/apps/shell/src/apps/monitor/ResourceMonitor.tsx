import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api, errorMessage, unwrap } from "../../api";
import { bitsPerSecond, bytes, dateTime, duration, relativeTime } from "../../format";
import { useJobs, useMetrics } from "../../hooks/queries";
import { Button, Card, EmptyState, ErrorBox, Loading, PageHeader, Progress, Stat } from "../../ui";
import { AreaChart } from "../../ui/Chart";
import { toast } from "../../ui/toasts";
import { JobStateBadge } from "../shared";

export default function ResourceMonitor() {
  const metrics = useMetrics(2_000);
  const jobs = useJobs(50);
  const qc = useQueryClient();
  const cancel = useMutation({
    mutationFn: (id: string) => unwrap(api.POST("/jobs/{id}/cancel", { params: { path: { id } } })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["jobs"] }),
    onError: (err) => toast("error", "Couldn't cancel", errorMessage(err)),
  });

  const m = metrics.data;
  const cur = m?.current;
  const hist = m?.history ?? [];

  return (
    <div className="app-layout__content">
      <PageHeader title="Resource Monitor" subtitle={cur ? `Up ${duration(cur.uptimeSecs)} · load ${cur.load1.toFixed(2)} on ${m?.cpus ?? "?"} CPU threads` : "Collecting…"} />
      {metrics.isError ? (
        <ErrorBox error={metrics.error} onRetry={() => metrics.refetch()} />
      ) : !cur ? (
        <Loading />
      ) : (
        <>
          <div className="grid-4">
            <Stat label="CPU" value={<span className="mono">{Math.round(cur.cpuPercent)}%</span>} />
            <Stat label="Memory used" value={<span className="mono">{bytes(cur.memUsed, 1)}</span>} sub={`of ${bytes(cur.memTotal, 0)}`} />
            <Stat label="ZFS cache" value={<span className="mono">{bytes(cur.arcBytes, 1)}</span>} sub="Freed automatically when apps need memory" />
            <Stat label="Network" value={<span className="mono" style={{ fontSize: 15 }}>↓ {bitsPerSecond(cur.netRxBps)}</span>} sub={`↑ ${bitsPerSecond(cur.netTxBps)}`} />
          </div>
          <div className="grid-2">
            <Card title="CPU">
              <AreaChart values={hist.map((h) => h.cpuPercent)} max={100} label="CPU use over the last five minutes" />
              <span className="small muted">Last 5 minutes · 0-100%</span>
            </Card>
            <Card title="Memory">
              <AreaChart
                values={hist.map((h) => h.memUsed)}
                secondary={hist.map((h) => h.memUsed + h.arcBytes)}
                max={cur.memTotal}
                color="#2fbf71"
                label="Memory used by programs and by the ZFS cache"
              />
              <div className="legend">
                <span>
                  <span className="swatch" style={{ background: "#2fbf71" }} /> Programs
                </span>
                <span>
                  <span className="swatch" style={{ background: "var(--hos-violet)" }} /> Programs + ZFS cache
                </span>
              </div>
            </Card>
            <Card title="Network">
              <AreaChart values={hist.map((h) => h.netRxBps)} secondary={hist.map((h) => h.netTxBps)} label="Network download and upload" />
              <div className="legend">
                <span>
                  <span className="swatch" style={{ background: "var(--hos-accent)" }} /> Download
                </span>
                <span>
                  <span className="swatch" style={{ background: "var(--hos-violet)" }} /> Upload
                </span>
              </div>
            </Card>
            <Card title="Memory split">
              <div className="stack" style={{ gap: 8 }}>
                <div className="row row--between small">
                  <span>Programs</span>
                  <span className="mono">{Math.round((cur.memUsed / cur.memTotal) * 100)}%</span>
                </div>
                <Progress value={(cur.memUsed / cur.memTotal) * 100} tone="good" label="Memory used by programs" />
                <div className="row row--between small">
                  <span>ZFS cache</span>
                  <span className="mono">{Math.round((cur.arcBytes / cur.memTotal) * 100)}%</span>
                </div>
                <Progress value={(cur.arcBytes / cur.memTotal) * 100} tone="accent" label="Memory used by the ZFS cache" />
              </div>
            </Card>
          </div>
        </>
      )}

      <Card title="Jobs">
        {jobs.isPending ? (
          <Loading />
        ) : jobs.isError ? (
          <ErrorBox error={jobs.error} onRetry={() => jobs.refetch()} />
        ) : jobs.data.length === 0 ? (
          <EmptyState title="No jobs yet">Long operations like creating a pool or replacing a disk show up here.</EmptyState>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Job</th>
                  <th>State</th>
                  <th>Progress</th>
                  <th>Started</th>
                  <th className="actions">
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {jobs.data.map((j) => (
                  <tr key={j.id}>
                    <td>
                      {j.title}
                      <span className="cell-sub">{j.state === "failed" ? j.error : j.message}</span>
                    </td>
                    <td>
                      <JobStateBadge state={j.state} />
                    </td>
                    <td style={{ width: 160 }}>
                      {j.state === "running" || j.state === "queued" ? <Progress value={j.progress} label={`${j.title} progress`} /> : <span className="small muted">{Math.round(j.progress)}%</span>}
                    </td>
                    <td title={dateTime(j.createdAt)}>{relativeTime(j.startedAt ?? j.createdAt)}</td>
                    <td className="actions">
                      {(j.state === "running" || j.state === "queued") && (
                        <Button size="sm" onClick={() => cancel.mutate(j.id)} busy={cancel.isPending && cancel.variables === j.id}>
                          Cancel
                        </Button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
