import type { Disk, DiskInfo, SMART } from "@hardy/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, errorMessage, unwrap } from "../../api";
import { bytes, dateTime, relativeTime } from "../../format";
import { useDiskInfo } from "../../hooks/monitoring";
import { Alert, Badge, Button, ErrorBox, Loading, PageHeader, Progress, type Tone } from "../../ui";
import { Dialog } from "../../ui/Dialog";
import { toast } from "../../ui/toasts";

const USAGE: Record<Disk["usage"], [string, Tone]> = {
  free: ["Unused", "good"],
  "has-data": ["Old data", "warn"],
  pool: ["In a pool", "accent"],
  boot: ["System", "neutral"],
  mounted: ["Mounted", "neutral"],
};
const HEALTH_TONE: Record<string, Tone> = { good: "good", warning: "warn", failing: "bad", unknown: "neutral" };
const HEALTH_LABEL: Record<string, string> = { good: "Healthy", warning: "Wear", failing: "Failing", unknown: "Unknown" };

function nextTest(d: DiskInfo): string {
  const t = d.tests;
  if (!t) return "Not scheduled yet";
  if (t.running) return `${t.running === "long" ? "Long" : "Short"} test running`;
  if (t.excluded) return "Automatic tests off";
  const short = new Date(t.nextShortAt).getTime();
  const long = new Date(t.nextLongAt).getTime();
  const [kind, at] = long <= short ? ["long", t.nextLongAt] : ["short", t.nextShortAt];
  return `Next ${kind} test ${relativeTime(at)}`;
}

export function Disks({ initial }: { initial?: string }) {
  const q = useDiskInfo();
  const qc = useQueryClient();
  const [open, setOpen] = useState<string | null>(initial ?? null);

  if (q.isPending) return <Loading />;
  if (q.isError) return <ErrorBox error={q.error} onRetry={() => q.refetch()} />;
  const selected = q.data.find((d) => d.disk.name === open);

  return (
    <>
      <PageHeader
        title="Disks"
        subtitle="Every disk HardyOS can see, its SMART health and its self-test schedule. Select one for the full report."
        actions={
          <Button onClick={() => void qc.invalidateQueries({ queryKey: ["disk-info"] })} busy={q.isFetching}>
            Rescan
          </Button>
        }
      />
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Disk</th>
              <th>Model</th>
              <th className="num">Size</th>
              <th>Used for</th>
              <th>Health</th>
              <th className="num">Temp.</th>
              <th>Self-tests</th>
            </tr>
          </thead>
          <tbody>
            {q.data.map((di) => {
              const d = di.disk;
              const s = di.smart;
              const [label, tone] = USAGE[d.usage];
              return (
                <tr key={d.name} className="is-clickable" tabIndex={0} onClick={() => setOpen(d.name)} onKeyDown={(e) => e.key === "Enter" && setOpen(d.name)}>
                  <td>
                    <strong className="mono">{d.name}</strong>
                    <span className="cell-sub mono" title={d.byId}>
                      {d.byId.replace("/dev/disk/by-id/", "")}
                    </span>
                  </td>
                  <td>
                    {d.model || "–"}
                    <span className="cell-sub">
                      {d.kind.toUpperCase()}
                      {d.removable ? " · removable" : ""} · {d.serial}
                    </span>
                  </td>
                  <td className="num">{bytes(d.sizeBytes, 0)}</td>
                  <td>
                    <Badge tone={tone}>{d.pool ? `${label}: ${d.pool}` : label}</Badge>
                  </td>
                  <td>
                    {s ? (
                      <>
                        <Badge tone={HEALTH_TONE[s.health] ?? "neutral"}>{HEALTH_LABEL[s.health] ?? s.health}</Badge>
                        {di.readAt && <span className="cell-sub">read {relativeTime(di.readAt)}</span>}
                      </>
                    ) : (
                      <span className="muted small">{d.removable ? "Not checked (removable)" : "Not read yet"}</span>
                    )}
                  </td>
                  <td className="num mono">{s?.temperatureC != null ? `${s.temperatureC} °C` : "–"}</td>
                  <td className="small">
                    {nextTest(di)}
                    {di.tests?.lastResult && (
                      <span className="cell-sub">
                        Last {di.tests.lastType}: {di.tests.lastResult}
                      </span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {selected && <SmartDialog info={selected} onClose={() => setOpen(null)} />}
    </>
  );
}

function SmartDialog({ info, onClose }: { info: DiskInfo; onClose: () => void }) {
  const disk = info.disk;
  const [tab, setTab] = useState<"summary" | "attributes" | "tests">("summary");
  const qc = useQueryClient();
  // A live reading (wakes the disk if it sleeps).
  const q = useQuery({
    queryKey: ["smart", disk.name],
    queryFn: () => unwrap(api.GET("/hardware/disks/{name}/smart", { params: { path: { name: disk.name } } })),
    retry: false,
  });
  const run = useMutation({
    mutationFn: (test: "short" | "long") => unwrap(api.POST("/monitor/disks/{name}/test", { params: { path: { name: disk.name } }, body: { test } })),
    onSuccess: (_, test) => {
      toast("info", `${test === "long" ? "Long" : "Short"} self-test started on ${disk.name}`, "The result shows here and as a notification when it finishes.");
      void qc.invalidateQueries({ queryKey: ["disk-info"] });
    },
  });
  const s: SMART | undefined = q.data ?? info.smart ?? undefined;
  const running = info.tests?.running || s?.selfTest.running;

  return (
    <Dialog title={`${disk.name} health`} description={`${disk.model || "Unknown model"} · ${disk.serial || "no serial"} · ${bytes(disk.sizeBytes, 0)}`} onClose={onClose} width={640}>
      <div className="tabs" role="tablist" aria-label="Disk health sections">
        {(
          [
            ["summary", "Summary"],
            ["attributes", "Attributes"],
            ["tests", "Self-tests"],
          ] as const
        ).map(([id, label]) => (
          <button key={id} type="button" role="tab" className="tabs__tab" aria-selected={tab === id} onClick={() => setTab(id)}>
            {label}
          </button>
        ))}
      </div>
      {q.isPending && !s ? (
        <Loading label="Reading SMART data…" />
      ) : q.isError && !s ? (
        <ErrorBox error={q.error} onRetry={() => q.refetch()} />
      ) : (
        s && (
          <div className="stack" style={{ marginTop: 12 }}>
            {tab === "summary" && <Summary s={s} />}
            {tab === "attributes" && <Attributes s={s} />}
            {tab === "tests" && (
              <>
                {running && (
                  <Alert tone="info" title={`A ${info.tests?.running || "self"} test is running`}>
                    {s.selfTest.remainingPct != null ? <Progress value={100 - s.selfTest.remainingPct} label="Self-test progress" /> : s.selfTest.status}
                  </Alert>
                )}
                <div className="row" style={{ gap: 8 }}>
                  <Button onClick={() => run.mutate("short")} disabled={!!running} busy={run.isPending && run.variables === "short"}>
                    Run short test{s.selfTest.shortMinutes ? ` (~${s.selfTest.shortMinutes} min)` : ""}
                  </Button>
                  <Button onClick={() => run.mutate("long")} disabled={!!running} busy={run.isPending && run.variables === "long"}>
                    Run long test{s.selfTest.longMinutes ? ` (~${Math.round(s.selfTest.longMinutes / 60)} h)` : ""}
                  </Button>
                </div>
                {run.error != null && <Alert tone="bad">{errorMessage(run.error)}</Alert>}
                {info.tests && (
                  <dl className="kv">
                    <dt>Next short test</dt>
                    <dd title={dateTime(info.tests.nextShortAt)}>{relativeTime(info.tests.nextShortAt)}</dd>
                    <dt>Next long test</dt>
                    <dd title={dateTime(info.tests.nextLongAt)}>{relativeTime(info.tests.nextLongAt)}</dd>
                    {info.tests.lastDoneAt && (
                      <>
                        <dt>Last result</dt>
                        <dd>
                          {info.tests.lastType} · {info.tests.lastResult} · {relativeTime(info.tests.lastDoneAt)}
                        </dd>
                      </>
                    )}
                  </dl>
                )}
                {s.selfTests.length === 0 ? (
                  <p className="small muted">The drive's self-test log is empty.</p>
                ) : (
                  <div className="table-wrap">
                    <table className="table">
                      <thead>
                        <tr>
                          <th>Test</th>
                          <th>Result</th>
                          <th className="num">At hour</th>
                        </tr>
                      </thead>
                      <tbody>
                        {s.selfTests.map((t, i) => (
                          <tr key={i}>
                            <td>{t.type}</td>
                            <td>
                              <Badge tone={t.passed == null ? "neutral" : t.passed ? "good" : "bad"}>{t.status}</Badge>
                            </td>
                            <td className="num mono">{t.hours?.toLocaleString() ?? "–"}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </>
            )}
          </div>
        )
      )}
    </Dialog>
  );
}

function Summary({ s }: { s: SMART }) {
  const row = (label: string, value: string | number | null | undefined) =>
    value == null ? null : (
      <div style={{ display: "contents" }}>
        <dt>{label}</dt>
        <dd className="mono">{value}</dd>
      </div>
    );
  const tone = HEALTH_TONE[s.health] === "good" ? "good" : HEALTH_TONE[s.health] === "bad" ? "bad" : HEALTH_TONE[s.health] === "warn" ? "warn" : "info";
  return (
    <>
      {s.standby ? (
        <Alert tone="info" title="The disk is asleep">
          It wasn't woken up to read it. Its last reading is shown.
        </Alert>
      ) : (
        <Alert tone={tone} title={`Health: ${HEALTH_LABEL[s.health] ?? s.health}`}>
          {s.reasons.length ? s.reasons.join("; ") : "No problems reported."}
        </Alert>
      )}
      <dl className="kv">
        {row("Protocol", s.protocol || null)}
        {row("Firmware", s.firmware || null)}
        {row("Self-assessment", s.passed == null ? null : s.passed ? "Passed" : "Failed")}
        {row("Temperature", s.temperatureC != null ? `${s.temperatureC} °C` : null)}
        {row("Power-on time", s.powerOnHours != null ? `${s.powerOnHours.toLocaleString()} h (${(s.powerOnHours / 8766).toFixed(1)} years)` : null)}
        {row("Power cycles", s.powerCycles)}
        {row("Rotation", s.rotationRpm ? `${s.rotationRpm} rpm` : null)}
        {row("Reallocated sectors", s.reallocated)}
        {row("Pending sectors", s.pending)}
        {row("Uncorrectable sectors", s.uncorrectable)}
        {row("Reported uncorrectable", s.reportedUncorrect)}
        {row("Cable (CRC) errors", s.crcErrors)}
        {row("Grown defects", s.grownDefects)}
        {row("Uncorrected errors", s.uncorrectedErrors)}
        {row("Endurance used", s.percentUsed != null ? `${s.percentUsed}%` : null)}
        {row("Spare blocks", s.availableSpare != null ? `${s.availableSpare}% (threshold ${s.spareThreshold ?? "?"}%)` : null)}
        {row("Media errors", s.mediaErrors)}
        {row("Unsafe shutdowns", s.unsafeShutdowns)}
        {row("Critical warning", s.criticalWarning != null ? `0x${s.criticalWarning.toString(16).padStart(2, "0")}` : null)}
      </dl>
    </>
  );
}

const KEY_ATTRS = new Set([5, 187, 188, 197, 198, 199]);

function Attributes({ s }: { s: SMART }) {
  if (s.attributes.length === 0) return <p className="small muted">This drive ({s.protocol || "its type"}) has no ATA attribute table; the summary shows its counters.</p>;
  return (
    <div className="table-wrap">
      <table className="table">
        <thead>
          <tr>
            <th className="num">ID</th>
            <th>Attribute</th>
            <th className="num">Value</th>
            <th className="num">Worst</th>
            <th className="num">Threshold</th>
            <th className="num">Raw</th>
          </tr>
        </thead>
        <tbody>
          {s.attributes.map((a) => {
            const bad = a.whenFailed !== "" || (KEY_ATTRS.has(a.id) && a.raw > 0 && a.id !== 199);
            return (
              <tr key={a.id}>
                <td className="num mono">{a.id}</td>
                <td>
                  {a.name.replace(/_/g, " ")}
                  {a.whenFailed && <span className="cell-sub" style={{ color: "var(--hos-bad-text)" }}>Failed {a.whenFailed}</span>}
                </td>
                <td className="num mono">{a.value}</td>
                <td className="num mono">{a.worst}</td>
                <td className="num mono">{a.thresh}</td>
                <td className="num mono">{bad ? <Badge tone="warn">{a.rawString || a.raw}</Badge> : a.rawString || a.raw}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
