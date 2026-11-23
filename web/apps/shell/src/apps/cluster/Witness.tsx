import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, errorMessage, unwrap } from "../../api";
import { dateTime } from "../../format";
import { Alert, Badge, Button, Card, Field, PageHeader, TextInput } from "../../ui";
import { Dialog } from "../../ui/Dialog";
import { JobProgress } from "../shared";
import type { ClusterStatus } from "../../cluster/scope";
import { PathChips } from "./Overview";

/**
 * The witness setup page: the witness runs on the VPS (plain Ubuntu, in
 * the same NetBird network), votes only when the number of HardyOS voters
 * is even and runs nothing. A one-time script installs and joins it.
 */
export function Witness({ st }: { st: ClusterStatus }) {
  const witness = st.nodes.find((n) => n.role === "witness");
  const self = st.nodes.find((n) => n.id === st.self);
  const [script, setScript] = useState<{ script: string; expires: string } | null>(null);
  const [removing, setRemoving] = useState(false);
  const make = useMutation({ mutationFn: () => unwrap(api.POST("/cluster/witness/script")), onSuccess: setScript });
  const download = () => {
    if (!script) return;
    const url = URL.createObjectURL(new Blob([script.script], { type: "text/x-shellscript" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = "hardyos-witness.sh";
    a.click();
    URL.revokeObjectURL(url);
  };
  return (
    <div className="stack">
      <PageHeader title="Witness" subtitle="A tie-breaking vote on the VPS, reached over NetBird only." />
      {witness ? (
        <Card title="The witness">
          <div className="stack">
            <div className="row">
              <strong>{witness.name}</strong>
              <Badge tone={witness.live === "voter" ? "accent" : "neutral"}>{witness.live === "voter" ? "voting" : "standby"}</Badge>
              <Badge tone="neutral">{witness.state}</Badge>
              <PathChips n={witness} />
            </div>
            <p className="small muted">
              It votes while the number of voting servers is even (two servers, or three with one in maintenance), holds the cluster log and signs
              nothing but its own hello. To update it, run a new script; to remove it, remove it here and then run the script with --remove on the
              VPS.
            </p>
            <div className="row">
              <Button onClick={() => make.mutate()} busy={make.isPending}>
                New install script
              </Button>
              <Button variant="danger" onClick={() => setRemoving(true)}>
                Remove the witness…
              </Button>
            </div>
          </div>
        </Card>
      ) : (
        <Card title="Add the witness">
          <div className="stack">
            {!self?.addresses.netbird ? (
              <Alert tone="warn" title="This server isn't on NetBird">
                The witness is reached over NetBird only. Join this server to NetBird in Control Panel › Remote Access first.
              </Alert>
            ) : (
              <>
                <ol className="small">
                  <li>Join the VPS to the same NetBird network.</li>
                  <li>Make the install script here (it carries a one-time code, valid 30 minutes).</li>
                  <li>
                    Run it as root on the VPS: <span className="mono">sudo sh hardyos-witness.sh</span>
                  </li>
                </ol>
                <div>
                  <Button variant="primary" busy={make.isPending} onClick={() => make.mutate()}>
                    Make the install script
                  </Button>
                </div>
              </>
            )}
          </div>
        </Card>
      )}
      {make.error && <Alert tone="bad">{errorMessage(make.error)}</Alert>}
      {script && (
        <Card title="Install script" actions={<Button onClick={download}>Download</Button>}>
          <div className="stack">
            <p className="small">
              Valid until {dateTime(script.expires)}, once. It downloads the witness from this server over NetBird (checking this server's key and the
              file's checksum) and installs a sandboxed service.
            </p>
            <pre className="cluster-script">{script.script}</pre>
          </div>
        </Card>
      )}
      {removing && witness && <RemoveWitness id={witness.id} name={witness.name} onClose={() => setRemoving(false)} />}
    </div>
  );
}

function RemoveWitness({ id, name, onClose }: { id: string; name: string; onClose: () => void }) {
  const [confirm, setConfirm] = useState("");
  const [job, setJob] = useState<string | null>(null);
  const qc = useQueryClient();
  const m = useMutation({
    mutationFn: () => unwrap(api.DELETE("/cluster/nodes/{node}", { params: { path: { node: id } }, body: { confirm } })),
    onSuccess: (r) => setJob(r.job.id),
  });
  return (
    <Dialog
      title="Remove the witness"
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose}>{job ? "Close" : "Cancel"}</Button>
          {!job && (
            <Button variant="danger" busy={m.isPending} disabled={confirm !== name && confirm !== id} onClick={() => m.mutate()}>
              Remove
            </Button>
          )}
        </>
      }
    >
      <div className="stack">
        <p>The witness leaves the cluster and its key is refused. Then run the install script with --remove on the VPS.</p>
        {!job && <Field label={`Type ${name} to confirm`}>{(fid) => <TextInput id={fid} value={confirm} onChange={(e) => setConfirm(e.target.value)} />}</Field>}
        {m.error && <Alert tone="bad">{errorMessage(m.error)}</Alert>}
        {job && <JobProgress id={job} onDone={() => qc.invalidateQueries({ queryKey: ["cluster"] })} />}
      </div>
    </Dialog>
  );
}
