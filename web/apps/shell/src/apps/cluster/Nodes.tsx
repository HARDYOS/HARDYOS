import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, errorMessage, unwrap } from "../../api";
import { Alert, Badge, Button, Card, Dot, Field, PageHeader, TextInput } from "../../ui";
import { Dialog } from "../../ui/Dialog";
import { JobProgress } from "../shared";
import { type ClusterNodeStatus, type ClusterStatus } from "../../cluster/scope";
import { PathChips, nodeTone } from "./Overview";

/** Servers: leave this one, remove a dead one, dissolve from the last one. */
export function Nodes({ st }: { st: ClusterStatus }) {
  const [removing, setRemoving] = useState<ClusterNodeStatus | null>(null);
  const [leaving, setLeaving] = useState<"leave" | "dissolve" | null>(null);
  const others = st.nodes.filter((n) => n.role !== "witness" && n.id !== st.self).length;
  return (
    <div className="stack">
      <PageHeader
        title="Servers"
        actions={
          others > 0 ? (
            <Button variant="danger" onClick={() => setLeaving("leave")}>
              Leave the cluster
            </Button>
          ) : (
            <Button variant="danger" onClick={() => setLeaving("dissolve")}>
              Dissolve the cluster
            </Button>
          )
        }
      />
      <Card>
        <table className="table">
          <thead>
            <tr>
              <th>Server</th>
              <th>Role</th>
              <th>State</th>
              <th>Vote</th>
              <th>Path</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {st.nodes.map((n) => (
              <tr key={n.id}>
                <td>
                  <Dot tone={nodeTone(st, n)} /> {n.name} {n.id === st.self && <Badge tone="info">this server</Badge>}
                </td>
                <td>{n.role}</td>
                <td>{n.state}</td>
                <td>{n.live === "voter" ? "voter" : "standby"}</td>
                <td>
                  <PathChips n={n} />
                </td>
                <td>
                  {n.id !== st.self && (
                    <Button size="sm" variant="ghost" onClick={() => setRemoving(n)}>
                      Remove…
                    </Button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
      {removing && <RemoveDialog n={removing} onClose={() => setRemoving(null)} />}
      {leaving && <LeaveDialog st={st} mode={leaving} onClose={() => setLeaving(null)} />}
    </div>
  );
}

function RemoveDialog({ n, onClose }: { n: ClusterNodeStatus; onClose: () => void }) {
  const [confirm, setConfirm] = useState("");
  const [job, setJob] = useState<string | null>(null);
  const qc = useQueryClient();
  const m = useMutation({
    mutationFn: () => unwrap(api.DELETE("/cluster/nodes/{node}", { params: { path: { node: n.id } }, body: { confirm } })),
    onSuccess: (r) => setJob(r.job.id),
  });
  return (
    <Dialog
      title={`Remove ${n.name}`}
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose}>{job ? "Close" : "Cancel"}</Button>
          {!job && (
            <Button variant="danger" busy={m.isPending} disabled={confirm !== n.name} onClick={() => m.mutate()}>
              Remove
            </Button>
          )}
        </>
      }
    >
      <div className="stack">
        <p>
          {n.name} is taken out of the cluster and its key is refused from then on. Use this for a server that is dead or gone; a working server
          should leave by itself (Servers › Leave on it). To join again it must be reset.
        </p>
        {!job && (
          <Field label={`Type ${n.name} to confirm`}>{(id) => <TextInput id={id} value={confirm} onChange={(e) => setConfirm(e.target.value)} />}</Field>
        )}
        {m.error && <Alert tone="bad">{errorMessage(m.error)}</Alert>}
        {job && <JobProgress id={job} onDone={() => qc.invalidateQueries({ queryKey: ["cluster"] })} />}
      </div>
    </Dialog>
  );
}

function LeaveDialog({ st, mode, onClose }: { st: ClusterStatus; mode: "leave" | "dissolve"; onClose: () => void }) {
  const [confirm, setConfirm] = useState("");
  const [job, setJob] = useState<string | null>(null);
  const qc = useQueryClient();
  const m = useMutation({
    mutationFn: () => unwrap(mode === "leave" ? api.POST("/cluster/leave", { body: { confirm } }) : api.POST("/cluster/dissolve", { body: { confirm } })),
    onSuccess: (r) => setJob(r.job.id),
  });
  const name = st.name ?? "";
  return (
    <Dialog
      title={mode === "leave" ? "Leave the cluster" : "Dissolve the cluster"}
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose}>{job ? "Close" : "Cancel"}</Button>
          {!job && (
            <Button variant="danger" busy={m.isPending} disabled={confirm !== name} onClick={() => m.mutate()}>
              {mode === "leave" ? "Leave" : "Dissolve"}
            </Button>
          )}
        </>
      }
    >
      <div className="stack">
        <p>
          {mode === "leave"
            ? "This server hands its vote over, is removed from the cluster and forgets its cluster key. Cluster workloads must be moved off it first."
            : "This is the cluster's last server: the cluster ends and this server forgets it."}
        </p>
        {!job && <Field label={`Type ${name} to confirm`}>{(id) => <TextInput id={id} value={confirm} onChange={(e) => setConfirm(e.target.value)} />}</Field>}
        {m.error && <Alert tone="bad">{errorMessage(m.error)}</Alert>}
        {job && <JobProgress id={job} onDone={() => qc.invalidateQueries({ queryKey: ["cluster"] })} />}
      </div>
    </Dialog>
  );
}
