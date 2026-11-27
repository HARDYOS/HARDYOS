import type { ClusterWindow } from "@hardy/api-client";
import { useQuery } from "@tanstack/react-query";
import { api, unwrap } from "../../api";
import { ExternalIcon } from "../../icons";
import { Badge, Button, Card } from "../../ui";
import { openInNewTab } from "./AppFrame";
import { STATE } from "./common";

/** Apps on the cluster's other servers that this person may open (each server decides). */
export const useClusterWindows = () =>
  useQuery({
    queryKey: ["cluster", "windows"],
    queryFn: () => unwrap(api.GET("/cluster/windows")),
    refetchInterval: 30_000,
    retry: false,
  });

/** The label for where a window opens: a cluster app follows its server. */
export function whereLabel(w: Pick<ClusterWindow, "nodeName" | "node" | "cluster">): string {
  const name = w.nodeName || w.node;
  return w.cluster ? `cluster app, now on ${name}` : `on ${name}`;
}

/**
 * "On other servers" in My apps: windows of apps that run on another
 * member open here, through this server's window proxy and the cluster
 * relay. Nothing is shown outside a cluster.
 */
export function OtherServers({ onOpen }: { onOpen: (app: { id: string; name: string }, node: string) => void }) {
  const q = useClusterWindows();
  const list = q.data ?? [];
  if (list.length === 0) return null;
  return (
    <Card title="On other servers">
      <ul className="app-other-list">
        {list.map((w) => {
          const st = STATE[w.state as keyof typeof STATE];
          return (
            <li key={`${w.node}/${w.id}`} className="app-other-row">
              <span className="app-other-row__name">{w.name}</span>
              <Badge tone={w.cluster ? "accent" : "neutral"}>{whereLabel(w)}</Badge>
              {st && <Badge tone={st.tone}>{st.label}</Badge>}
              <span className="app-card__spacer" />
              <Button size="sm" variant="primary" onClick={() => onOpen({ id: w.id, name: w.name }, w.node)}>
                Open
              </Button>
              <Button size="sm" variant="ghost" onClick={() => openInNewTab(w.id, w.name, w.node)} aria-label={`Open ${w.name} in a new tab`} title="Open in new tab">
                <ExternalIcon size={14} />
              </Button>
            </li>
          );
        })}
      </ul>
    </Card>
  );
}
