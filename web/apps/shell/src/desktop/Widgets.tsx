import type { User } from "@hardy/api-client";
import { bitsPerSecond, bytes, duration } from "../format";
import { useMetrics, usePools, useSystemInfo } from "../hooks/queries";
import { Badge, Progress } from "../ui";
import { BarSpark } from "../ui/Chart";
import { openApp } from "../wm/open";

function healthTone(h: string) {
  return h === "ONLINE" ? "good" : h === "DEGRADED" ? "warn" : "bad";
}

/** The right-hand widget column on the desktop. */
export function Widgets({ user }: { user: User }) {
  const isAdmin = user.role === "admin";
  const info = useSystemInfo();
  const metrics = useMetrics(5_000);
  const pools = usePools(isAdmin);
  const cur = metrics.data?.current;
  const history = metrics.data?.history ?? [];

  return (
    <aside className="widgets" aria-label="Widgets">
      <div className="widget glass">
        <div className="widget__row">
          <span className="widget__title">{info.data?.hostname ?? "HardyOS"}</span>
          <Badge tone="good">Healthy</Badge>
        </div>
        <div className="widget__row widget__muted">
          <span>HardyOS {info.data?.version ?? ""}</span>
          <span>Up {duration(info.data?.uptimeSecs)}</span>
        </div>
      </div>

      {isAdmin &&
        (pools.data?.length ? (
          pools.data.slice(0, 2).map((p) => (
            <button key={p.name} type="button" className="widget glass widget--button" onClick={() => openApp("os.hardy.storage", user, { pool: p.name })}>
              <div className="widget__row">
                <span className="widget__title">{p.name}</span>
                <Badge tone={healthTone(p.health)}>{p.health.toLowerCase()}</Badge>
              </div>
              <div className="widget__big">
                <span className="mono">{bytes(p.allocBytes)}</span>
                <span className="widget__muted">of {bytes(p.sizeBytes)}</span>
              </div>
              <Progress value={p.capacityPct} label={`${p.name} ${p.capacityPct}% used`} tone={p.capacityPct > 85 ? "warn" : "accent"} />
            </button>
          ))
        ) : pools.isSuccess ? (
          <button type="button" className="widget glass widget--button" onClick={() => openApp("os.hardy.storage", user)}>
            <span className="widget__title">No storage pool yet</span>
            <span className="widget__muted">Open Storage Manager to create one</span>
          </button>
        ) : null)}

      <div className="widget glass">
        <div className="widget__row">
          <span className="widget__title">CPU</span>
          <span className="mono">{cur ? `${Math.round(cur.cpuPercent)}%` : "–"}</span>
        </div>
        <BarSpark values={history.map((h) => h.cpuPercent)} label="CPU use over the last minutes" />
        <div className="widget__row">
          <span className="widget__title">Memory</span>
          <span className="mono">{cur ? `${bytes(cur.memUsed, 0)} / ${bytes(cur.memTotal, 0)}` : "–"}</span>
        </div>
        <Progress value={cur && cur.memTotal ? (cur.memUsed / cur.memTotal) * 100 : 0} tone="good" label="Memory used" />
        {cur && cur.arcBytes > 0 && <span className="widget__muted">ZFS cache using {bytes(cur.arcBytes, 0)}</span>}
      </div>

      <div className="widget glass">
        <div className="widget__row">
          <span className="widget__title">Network</span>
        </div>
        <div className="widget__pair">
          <div>
            <span className="widget__muted">Download</span>
            <span className="mono widget__num">{bitsPerSecond(cur?.netRxBps)}</span>
          </div>
          <div>
            <span className="widget__muted">Upload</span>
            <span className="mono widget__num">{bitsPerSecond(cur?.netTxBps)}</span>
          </div>
        </div>
      </div>
    </aside>
  );
}
