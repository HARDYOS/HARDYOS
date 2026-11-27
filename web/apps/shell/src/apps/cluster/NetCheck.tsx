import type { ClusterNetcheck, ClusterNetcheckMember, ClusterNetcheckPath } from "@hardy/api-client";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, errorMessage, unwrap } from "../../api";
import { rtt } from "../../cluster/scope";
import { relativeTime } from "../../format";
import { RefreshIcon } from "../../icons";
import { Alert, Badge, Button, Card, Dot, type Tone } from "../../ui";
import { toast } from "../../ui/toasts";

/** The local-network check (decisions 490-492), refreshed every 30 s. */
export const useNetcheck = (enabled = true) =>
  useQuery({
    queryKey: ["cluster", "netcheck"],
    queryFn: () => unwrap(api.GET("/cluster/netcheck")),
    refetchInterval: 30_000,
    enabled,
  });

/** One row of the table: a server's probes of one other server. */
export interface NetcheckRow {
  from: string;
  to: string;
  lan?: ClusterNetcheckPath;
  storage?: ClusterNetcheckPath;
}

/** Rows (server → peer) with the LAN and storage-network probes side by side. */
export function netcheckRows(r: ClusterNetcheck): NetcheckRow[] {
  const name = new Map(r.perMember.map((m) => [m.node, m.name || m.node]));
  const rows: NetcheckRow[] = [];
  for (const m of r.perMember) {
    if (m.skipped) continue;
    const byPeer = new Map<string, NetcheckRow>();
    for (const p of m.paths) {
      let row = byPeer.get(p.peer);
      if (!row) {
        row = { from: name.get(m.node) ?? m.node, to: name.get(p.peer) ?? p.peer };
        byPeer.set(p.peer, row);
        rows.push(row);
      }
      if (p.path === "lan") row.lan = p;
      if (p.path === "storage") row.storage = p;
    }
  }
  return rows;
}

/** A path's cell in words: RTT, same subnet or routed, the storage MTU. */
export function pathSummary(p: ClusterNetcheckPath | undefined): { tone: Tone; text: string } {
  if (!p) return { tone: "neutral", text: "–" };
  if (!p.answered) return { tone: "bad", text: "no answer" };
  const parts = [rtt(p.rtt), p.sameSubnet ? "same subnet" : "routed"];
  if (p.path === "storage" && p.mtu) parts.push(`MTU ${p.mtu}${p.peerMtu && p.peerMtu !== p.mtu ? `/${p.peerMtu}` : ""}`);
  return { tone: p.ok ? "good" : "bad", text: parts.join(" · ") };
}

function memberTone(m: ClusterNetcheckMember): Tone {
  if (m.skipped) return "neutral";
  return m.ok ? "good" : "warn";
}

/**
 * Cluster › Overview › Local network: whether the servers reach each other
 * directly on the LAN and the storage network. Live moves and turning high
 * availability on wait for it; the cluster works without it.
 */
export function NetCheckCard() {
  const q = useNetcheck();
  const qc = useQueryClient();
  const [busy, setBusy] = useState(false);
  const checkNow = async () => {
    setBusy(true);
    try {
      const r = await unwrap(api.GET("/cluster/netcheck", { params: { query: { fresh: "1" } } }));
      qc.setQueryData(["cluster", "netcheck"], r);
    } catch (err) {
      toast("error", "Couldn't check the network", errorMessage(err));
    } finally {
      setBusy(false);
    }
  };
  const r = q.data;
  const rows = r ? netcheckRows(r) : [];
  const failing = rows.flatMap((x) => [x.lan, x.storage]).filter((p): p is ClusterNetcheckPath => !!p && !p.ok);
  return (
    <Card
      title="Local network"
      actions={
        <Button size="sm" variant="ghost" busy={busy} onClick={checkNow} aria-label="Check the local network now" title="Check now">
          <RefreshIcon size={14} /> Check now
        </Button>
      }
    >
      {!r ? (
        <p className="muted small">{q.error ? errorMessage(q.error) : "Checking…"}</p>
      ) : (
        <div className="stack">
          {r.ok ? (
            <p className="small muted">
              Every server reaches the others directly on the LAN and on the storage network. Live moves and high availability can be used.
            </p>
          ) : (
            <Alert tone="warn" title="The servers don't share a local network yet">
              {r.reason}. The cluster keeps working (over NetBird where it must), but turning high availability on and live moves wait until
              every compute server and the storage server reach each other directly on the LAN and the storage network.
            </Alert>
          )}
          <div className="cluster-net__members">
            {r.perMember.map((m) => (
              <span key={m.node} className="cluster-net__member" title={m.reason}>
                <Dot tone={memberTone(m)} /> {m.name || m.node}
                {m.skipped && <Badge tone="neutral">not checked</Badge>}
                {m.checked && !m.skipped && <span className="muted small">{relativeTime(m.checked)}</span>}
              </span>
            ))}
          </div>
          {rows.length > 0 && (
            <div className="table-wrap">
              <table className="table cluster-net__table">
                <thead>
                  <tr>
                    <th>From</th>
                    <th>To</th>
                    <th>LAN</th>
                    <th>Storage network</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((x) => (
                    <tr key={`${x.from}>${x.to}`}>
                      <td>{x.from}</td>
                      <td>{x.to}</td>
                      {[x.lan, x.storage].map((p, i) => {
                        const s = pathSummary(p);
                        return (
                          <td key={i} title={p?.reason}>
                            <span className="cluster-net__cell">
                              <Dot tone={s.tone} /> <span className="mono small">{s.text}</span>
                            </span>
                          </td>
                        );
                      })}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {failing.length > 0 && (
            <ul className="cluster-net__problems small">
              {failing.map((p, i) => (
                <li key={i}>{p.reason}</li>
              ))}
            </ul>
          )}
        </div>
      )}
    </Card>
  );
}
