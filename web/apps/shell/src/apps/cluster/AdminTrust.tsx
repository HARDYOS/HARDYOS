import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, errorMessage, unwrap } from "../../api";
import { Alert, Card, Toggle } from "../../ui";

/**
 * Which other servers' administrators this server accepts (decision 368).
 * An administrator signed in on another member is an administrator here
 * too, within the cluster desktop's areas (workloads, storage, files,
 * apps, monitoring); never for accounts, the terminal, sign-in, network,
 * updates, remote access, custom apps or the cluster's membership. Each
 * server decides for itself; only its own administrators can change it.
 */
export function AdminTrust() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["cluster", "admin-trust"], queryFn: () => unwrap(api.GET("/cluster/admin-trust")) });
  const set = useMutation({
    mutationFn: (m: { id: string; name: string; accept: boolean }) =>
      unwrap(api.PUT("/cluster/admin-trust", { body: { members: [m] } })),
    onSuccess: (data) => qc.setQueryData(["cluster", "admin-trust"], data),
  });
  const members = q.data?.members ?? [];
  return (
    <Card title="Administrators of other servers">
      <div className="stack">
        <p className="small muted">
          An administrator signed in on another server of the cluster can manage this server's VMs, apps, storage, shared folders and files from
          the same desktop. They can never change this server's accounts, sign-in, network, updates, remote access or cluster membership, open its
          terminal or install custom apps: for those, sign in on this server. Turn a server off here to stop accepting its administrators at all.
        </p>
        {q.error && <Alert tone="bad">{errorMessage(q.error)}</Alert>}
        {set.error && <Alert tone="bad">{errorMessage(set.error)}</Alert>}
        {members.length === 0 && !q.isLoading && <p className="small muted">There are no other servers in the cluster.</p>}
        {members.map((m) => (
          <Toggle
            key={m.id}
            label={`Accept administrators of ${m.name}`}
            description={m.accept ? "Their administrators act as administrators here." : "Their administrators can't use this server."}
            checked={m.accept}
            disabled={set.isPending}
            onChange={(accept) => set.mutate({ id: m.id, name: m.name, accept })}
          />
        ))}
      </div>
    </Card>
  );
}
