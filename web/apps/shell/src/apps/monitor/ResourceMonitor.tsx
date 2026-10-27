import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, errorMessage, unwrap } from "../../api";
import { bitsPerSecond, bytes, dateTime, duration, relativeTime } from "../../format";
import { type HistoryRange, useHistory } from "../../hooks/monitoring";
import { useJobs, useMetrics } from "../../hooks/queries";
import { type AppProps, useShell } from "../../shell";
import { Button, Card, EmptyState, ErrorBox, Loading, PageHeader, Progress, Stat } from "../../ui";
import { AreaChart } from "../../ui/Chart";
import { type ChartSeries, TimeChart, foldSeries } from "../../ui/TimeChart";
import { toast } from "../../ui/toasts";
import { JobStateBadge } from "../shared";
import { ConditionList, RangePicker } from "./parts";

type Tab = "overview" | "history" | "apps" | "vms" | "alerts" | "jobs";

export default function ResourceMonitor({ args }: AppProps) {
  const { user } = useShell();
  const admin = user.role === "admin";
  const [tab, setTab] = useState<Tab>(admin ? ((args?.tab as Tab) ?? "overview") : "overview");
  const [range, setRange] = useState<HistoryRange>("24h");
  const tabs: [Tab, string][] = [
    ["overview", "Now"],
    // History names apps, VMs, pools and disks: administrators only.
    ...(admin
      ? ([
          ["history", "History"],
          ["apps", "Apps"],
          ["vms", "VMs"],
          ["alerts", "Alerts"],
        ] as [Tab, string][])
      : []),
    ["jobs", "Jobs"],
  ];
  return (
    <div className="app-layout__content">
      <div className="tabs" role="tablist" aria-label="Resource Monitor sections">
        {tabs.map(([id, label]) => (
          <button key={id} type="button" role="tab" className="tabs__tab" aria-selected={tab === id} onClick={() => setTab(id)}>
            {label}
          </button>
        ))}
      </div>
      {(tab === "history" || tab === "apps" || tab === "vms") && (
        <div className="range-row">
          <RangePicker value={range} onChange={setRange} />
          <span className="small muted">10-second detail for a day, then minutes, quarter hours and hours for up to two years.</span>
        </div>
      )}
      {tab === "overview" && <Live />}
      {tab === "history" && <History range={range} />}
      {tab === "apps" && <PerApp range={range} />}
      {tab === "vms" && <PerVM range={range} />}
      {tab === "alerts" && (
        <>
          <PageHeader title="Alerts" subtitle="What needs attention right now. Each one was sent once when it started and clears itself when fixed." />
          <ConditionList />
        </>
      )}
      {tab === "jobs" && <Jobs />}
    </div>
  );
}

/** One chart card over history: patterns name the series, labels rename them. */
function HistoryCard({
  title,
  series,
  unit,
  range,
  max,
  labels = {},
  sub,
}: {
  title: string;
  series: string[];
  unit: string;
  range: HistoryRange;
  max?: number;
  labels?: Record<string, string>;
  sub?: string;
}) {
  const q = useHistory(series, range, 300);
  const data = q.data;
  const lines: ChartSeries[] = (data?.series ?? [])
    .filter((s) => s.values.some((v) => v != null))
    .map((s) => ({ key: s.name, label: labels[s.name] ?? (s.label || s.name), values: s.values }));
  return (
    <Card title={title} actions={sub ? <span className="small muted">{sub}</span> : undefined}>
      {q.isError ? (
        <ErrorBox error={q.error} onRetry={() => q.refetch()} />
      ) : !data ? (
        <Loading />
      ) : (
        <div style={{ opacity: q.isFetching && q.isPlaceholderData ? 0.55 : 1, transition: "opacity .2s" }}>
          <TimeChart from={data.from} step={data.step} series={foldSeries(lines)} unit={unit} max={max} label={`${title}, ${range}`} />
        </div>
      )}
    </Card>
  );
}

function History({ range }: { range: HistoryRange }) {
  return (
    <div className="grid-2">
      <HistoryCard title="CPU" series={["cpu.percent"]} unit="percent" max={100} range={range} labels={{ "cpu.percent": "CPU" }} />
      <HistoryCard title="Memory" series={["mem.used", "mem.arc"]} unit="bytes" range={range} labels={{ "mem.used": "Programs", "mem.arc": "ZFS cache" }} />
      <HistoryCard title="Network" series={["net.rx", "net.tx"]} unit="bytes/s" range={range} labels={{ "net.rx": "Download", "net.tx": "Upload" }} />
      <HistoryCard title="Disk reads" series={["disk.read:*"]} unit="bytes/s" range={range} />
      <HistoryCard title="Disk writes" series={["disk.write:*"]} unit="bytes/s" range={range} />
      <HistoryCard title="Disk busy" series={["disk.busy:*"]} unit="percent" max={100} range={range} />
      <HistoryCard title="Temperatures" series={["temp:*", "disk.temp:*"]} unit="celsius" range={range} sub="Sensors found on this hardware" />
      <HistoryCard title="Pool space used" series={["pool.pct:*"]} unit="percent" max={100} range={range} />
      <HistoryCard title="UPS battery" series={["ups.charge:*"]} unit="percent" max={100} range={range} />
      <HistoryCard title="UPS load" series={["ups.load:*"]} unit="percent" max={100} range={range} />
    </div>
  );
}

function PerApp({ range }: { range: HistoryRange }) {
  return (
    <div className="grid-2">
      <HistoryCard title="CPU per app" series={["app.cpu:*"]} unit="percent" range={range} sub="Share of the whole server" />
      <HistoryCard title="Memory per app" series={["app.mem:*"]} unit="bytes" range={range} />
      <HistoryCard title="Disk reads per app" series={["app.read:*"]} unit="bytes/s" range={range} />
      <HistoryCard title="Disk writes per app" series={["app.write:*"]} unit="bytes/s" range={range} />
    </div>
  );
}

function PerVM({ range }: { range: HistoryRange }) {
  return (
    <div className="grid-2">
      <HistoryCard title="CPU per VM" series={["vm.cpu:*"]} unit="percent" range={range} />
      <HistoryCard title="Memory per VM" series={["vm.mem:*"]} unit="bytes" range={range} sub="What each guest uses" />
    </div>
  );
}

function Live() {
  const metrics = useMetrics(2_000);
  const m = metrics.data;
  const cur = m?.current;
  const hist = m?.history ?? [];
  return (
    <>
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
    </>
  );
}

function Jobs() {
  const jobs = useJobs(50);
  const qc = useQueryClient();
  const cancel = useMutation({
    mutationFn: (id: string) => unwrap(api.POST("/jobs/{id}/cancel", { params: { path: { id } } })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["jobs"] }),
    onError: (err) => toast("error", "Couldn't cancel", errorMessage(err)),
  });
  return (
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
  );
}
