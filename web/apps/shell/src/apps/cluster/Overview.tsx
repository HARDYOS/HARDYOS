import { relativeTime } from "../../format";
import { Alert, Badge, Card, Dot, PageHeader, Stat } from "../../ui";
import { type ClusterNodeStatus, type ClusterStatus, rtt } from "../../cluster/scope";

const PATHS = ["lan", "storage", "netbird"] as const;
const PATH_LABEL: Record<string, string> = { lan: "LAN", storage: "Storage", netbird: "NetBird", none: "none" };

/** The paths to a member: the one in use highlighted, failed ones struck. */
export function PathChips({ n }: { n: ClusterNodeStatus }) {
  const probes = n.path?.probes ?? [];
  if (!n.path) return <span className="muted small">this server</span>;
  return (
    <span className="cluster-path" aria-label={`Control path ${PATH_LABEL[n.path.current]}`}>
      {PATHS.filter((p) => probes.some((x) => x.path === p)).map((p) => {
        const pr = probes.find((x) => x.path === p);
        const cls = [n.path?.current === p ? "is-current" : "", pr && !pr.up ? "is-down" : ""].join(" ");
        return (
          <span key={p} className={cls} title={pr ? `${PATH_LABEL[p]} ${rtt(pr.rtt)}` : PATH_LABEL[p]}>
            {PATH_LABEL[p]}
          </span>
        );
      })}
    </span>
  );
}

export function nodeTone(st: ClusterStatus, n: ClusterNodeStatus): "good" | "warn" | "bad" {
  if (n.id === st.self) return st.quorate ? "good" : "warn";
  if (!n.health) return "warn";
  return n.health.suspect ? "bad" : "good";
}

export function Overview({ st }: { st: ClusterStatus }) {
  const servers = st.nodes.filter((n) => n.role !== "witness");
  const witness = st.nodes.find((n) => n.role === "witness");
  const voters = st.nodes.filter((n) => n.live === "voter").length;
  const reachable = st.nodes.filter((n) => n.live === "voter" && nodeTone(st, n) === "good").length;
  return (
    <div className="stack">
      <PageHeader title={st.name ?? "Cluster"} subtitle={`This server: ${st.self} (${st.role})`}
        badge={st.quorate ? <Badge tone="good">quorum</Badge> : <Badge tone="warn">no quorum</Badge>} />
      {st.halted && (
        <Alert tone="bad" title="This server stopped following the cluster">
          {st.halted}
        </Alert>
      )}
      {!st.quorate && !st.halted && (
        <Alert tone="warn" title="No quorum">
          This server can't reach a majority of the voters. Changes wait until it can; high-availability workloads here stop.
        </Alert>
      )}
      <div className="cluster-grid">
        <Stat label="Leader" value={st.leader || "–"} />
        <Stat label="Voters reachable" value={`${reachable} / ${voters}`} tone={reachable * 2 > voters ? "good" : "warn"} />
        <Stat label="Servers" value={servers.length} />
        <Stat label="Log index" value={<span className="mono">{st.index}</span>} sub={`term ${st.term}`} />
      </div>
      <Card title="Servers">
        <div className="cluster-grid">
          {servers.map((n) => (
            <NodeCard key={n.id} st={st} n={n} />
          ))}
        </div>
      </Card>
      <Card title="Witness">
        {witness ? (
          <NodeCard st={st} n={witness} />
        ) : (
          <p className="muted small">
            No witness yet. With an even number of servers (or one in maintenance) a witness on the VPS breaks ties; add one in Witness.
          </p>
        )}
      </Card>
    </div>
  );
}

function NodeCard({ st, n }: { st: ClusterStatus; n: ClusterNodeStatus }) {
  return (
    <div className="cluster-node card">
      <div className="cluster-node__head">
        <Dot tone={nodeTone(st, n)} />
        <span className="cluster-node__name">{n.name}</span>
        <Badge tone="neutral">{n.role}</Badge>
        {n.id === st.leader && <Badge tone="accent">leader</Badge>}
      </div>
      <dl className="cluster-node__meta">
        <dt>State</dt>
        <dd>{n.state}</dd>
        <dt>Vote</dt>
        <dd>{n.live === "voter" ? "voter" : "standby"}</dd>
        <dt>Version</dt>
        <dd>{n.version || "–"}</dd>
        <dt>Path</dt>
        <dd>
          <PathChips n={n} />
        </dd>
        <dt>RTT</dt>
        <dd>{rtt(n.path?.rtt)}</dd>
        {n.health && n.id !== st.self && (
          <>
            <dt>Heard</dt>
            <dd>{relativeTime(n.health.lastHeard)}</dd>
          </>
        )}
      </dl>
    </div>
  );
}
