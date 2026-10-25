import type { Disk } from "@hardy/api-client";
import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { api, unwrap } from "../../api";
import { bytes, relativeTime } from "../../format";
import { useDiskHealth, useHardware } from "../../hooks/queries";
import { Alert, Badge, Button, ErrorBox, Loading, PageHeader, type Tone } from "../../ui";
import { Dialog } from "../../ui/Dialog";

const USAGE: Record<Disk["usage"], [string, Tone]> = {
  free: ["Unused", "good"],
  "has-data": ["Old data", "warn"],
  pool: ["In a pool", "accent"],
  boot: ["System", "neutral"],
  mounted: ["Mounted", "neutral"],
};
const HEALTH_TONE: Record<string, Tone> = { good: "good", warning: "warn", failing: "bad", unknown: "neutral" };

export function Disks() {
  const hw = useHardware();
  const health = useDiskHealth();
  const [smartFor, setSmartFor] = useState<Disk | null>(null);
  const healthById = useMemo(() => new Map((health.data ?? []).map((h) => [h.byId, h])), [health.data]);

  if (hw.isPending) return <Loading />;
  if (hw.isError) return <ErrorBox error={hw.error} onRetry={() => hw.refetch()} />;

  return (
    <>
      <PageHeader title="Disks" subtitle="Every disk HardyOS can see. Select one for its full SMART health report." actions={<Button onClick={() => hw.refetch()} busy={hw.isFetching}>Rescan</Button>} />
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Disk</th>
              <th>Model</th>
              <th>Type</th>
              <th className="num">Size</th>
              <th>Used for</th>
              <th>Health</th>
            </tr>
          </thead>
          <tbody>
            {hw.data.disks.map((d) => {
              const h = healthById.get(d.byId);
              const [label, tone] = USAGE[d.usage];
              return (
                <tr key={d.name} className="is-clickable" tabIndex={0} onClick={() => setSmartFor(d)} onKeyDown={(e) => e.key === "Enter" && setSmartFor(d)}>
                  <td>
                    <strong className="mono">{d.name}</strong>
                    <span className="cell-sub mono" title={d.byId}>
                      {d.byId.replace("/dev/disk/by-id/", "")}
                    </span>
                  </td>
                  <td>
                    {d.model || "–"}
                    <span className="cell-sub">{d.serial}</span>
                  </td>
                  <td>
                    {d.kind.toUpperCase()}
                    {d.removable && <span className="cell-sub">removable</span>}
                  </td>
                  <td className="num">{bytes(d.sizeBytes, 0)}</td>
                  <td>
                    <Badge tone={tone}>{d.pool ? `${label}: ${d.pool}` : label}</Badge>
                    <span className="cell-sub">{d.usageDetail}</span>
                  </td>
                  <td>
                    {h ? (
                      <>
                        <Badge tone={HEALTH_TONE[h.health] ?? "neutral"}>{h.health}</Badge>
                        <span className="cell-sub">
                          {h.temperatureC != null ? `${h.temperatureC} °C · ` : ""}checked {relativeTime(h.checkedAt)}
                        </span>
                      </>
                    ) : (
                      <span className="muted small">Not checked yet</span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {smartFor && <SmartDialog disk={smartFor} onClose={() => setSmartFor(null)} />}
    </>
  );
}

function SmartDialog({ disk, onClose }: { disk: Disk; onClose: () => void }) {
  const q = useQuery({
    queryKey: ["smart", disk.name],
    queryFn: () => unwrap(api.GET("/hardware/disks/{name}/smart", { params: { path: { name: disk.name } } })),
    retry: false,
  });
  const s = q.data;
  const row = (label: string, value: string | number | null | undefined) =>
    value == null ? null : (
      <div style={{ display: "contents" }}>
        <dt>{label}</dt>
        <dd>{value}</dd>
      </div>
    );
  return (
    <Dialog title={`${disk.name} health`} description={`${disk.model || "Unknown model"} · ${disk.serial || "no serial"} · ${bytes(disk.sizeBytes, 0)}`} onClose={onClose} width={520}>
      {q.isPending ? (
        <Loading label="Reading SMART data…" />
      ) : q.isError ? (
        <ErrorBox error={q.error} onRetry={() => q.refetch()} />
      ) : (
        s && (
          <div className="stack">
            <Alert tone={HEALTH_TONE[s.health] === "good" ? "good" : HEALTH_TONE[s.health] === "bad" ? "bad" : HEALTH_TONE[s.health] === "warn" ? "warn" : "info"} title={`Health: ${s.health}`}>
              {s.reasons.length ? s.reasons.join("; ") : "No problems reported."}
            </Alert>
            <dl className="kv">
              {row("Self-assessment", s.passed == null ? null : s.passed ? "Passed" : "Failed")}
              {row("Temperature", s.temperatureC != null ? `${s.temperatureC} °C` : null)}
              {row("Power-on time", s.powerOnHours != null ? `${s.powerOnHours.toLocaleString()} hours (${(s.powerOnHours / 8766).toFixed(1)} years)` : null)}
              {row("Rotation", s.rotationRpm ? `${s.rotationRpm} rpm` : null)}
              {row("Reallocated sectors", s.reallocated)}
              {row("Pending sectors", s.pending)}
              {row("Uncorrectable sectors", s.uncorrectable)}
              {row("Cable (CRC) errors", s.crcErrors)}
              {row("Endurance used", s.percentUsed != null ? `${s.percentUsed}%` : null)}
              {row("Media errors", s.mediaErrors)}
            </dl>
          </div>
        )
      )}
    </Dialog>
  );
}
