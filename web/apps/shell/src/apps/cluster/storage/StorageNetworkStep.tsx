import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { ApiFailure, api, errorMessage, unwrap } from "../../../api";
import { Alert, Badge, Button, ErrorBox, Field, Loading, TextInput, Toggle } from "../../../ui";
import { PendingNetwork, useNetworkStatus } from "../../control-panel/Network";
import { JobProgress } from "../../shared";
import { type ClusterStorageCandidate, type ClusterStoragePlan, kindLabel, speed, storageKeys, useStorageNetwork } from "./api";

const key = (c: ClusterStorageCandidate) => `${c.kind}:${c.interface}`;

/**
 * The storage network step of the cluster create and join wizards (and the
 * Storage tab): pick how iSCSI and NFS reach the storage server, give this
 * server its address, and apply it like any network change (kept only
 * once confirmed). Storage traffic never goes over NetBird.
 */
export function StorageNetworkStep({ onDone }: { onDone?: (plan: ClusterStoragePlan) => void }) {
  const qc = useQueryClient();
  const info = useStorageNetwork();
  const net = useNetworkStatus();
  const [choice, setChoice] = useState<string>("");
  const [address, setAddress] = useState("");
  const [vlan, setVlan] = useState("77");
  const [jumbo, setJumbo] = useState(false);
  const [jobId, setJobId] = useState<string | null>(null);
  const [problems, setProblems] = useState<string[]>([]);

  useEffect(() => {
    const d = info.data;
    if (!d) return;
    if (!choice) {
      const saved = d.plan ? `${d.plan.kind}:${d.plan.interface}` : "";
      setChoice(saved || (d.candidates[0] ? key(d.candidates[0]) : ""));
    }
    if (!address) setAddress(d.plan?.address || d.suggested);
    if (d.plan?.vlan) setVlan(String(d.plan.vlan));
    if (d.plan?.mtu === 9000) setJumbo(true);
  }, [info.data, choice, address]);

  const cand = info.data?.candidates.find((c) => key(c) === choice);
  const plan: ClusterStoragePlan | null = cand
    ? { kind: cand.kind, interface: cand.interface, address, vlan: cand.kind === "vlan" ? Number(vlan) : undefined, mtu: jumbo ? 9000 : 0 }
    : null;

  const apply = useMutation({
    mutationFn: (p: ClusterStoragePlan) => unwrap(api.POST("/cluster/storage/network", { body: p })),
    onSuccess: (r) => {
      setProblems([]);
      setJobId(r.job.id);
    },
    onError: (e) => setProblems(e instanceof ApiFailure && e.details.length ? e.details : [errorMessage(e)]),
  });

  if (info.isLoading) return <Loading />;
  if (info.error) return <ErrorBox error={info.error} onRetry={() => void info.refetch()} />;
  const d = info.data!;
  const jumboOK = cand ? cand.kind !== "lan" && (d.jumbo[cand.interface] ?? false) : false;

  return (
    <div className="stack">
      <p className="muted">
        iSCSI disks and NFS folders between the servers go over a storage network: ideally its own port (10 Gb/s if you have it),
        never over NetBird. The addresses are fixed; the cluster uses {d.subnet}.
      </p>
      {net.data?.pending && <PendingNetwork pending={net.data.pending} />}
      {d.current && (
        <Alert tone="good" title={`This server is on the storage network: ${d.current} (${d.interface})`} />
      )}
      <fieldset className="stack" style={{ border: 0, padding: 0, margin: 0 }} aria-label="Storage network">
        {d.candidates.length === 0 && <Alert tone="warn" title="No network port can carry the storage network." />}
        {d.candidates.map((c) => (
          <label key={key(c)} className="row" style={{ gap: 10, alignItems: "flex-start" }}>
            <input type="radio" name="storage-port" checked={choice === key(c)} onChange={() => setChoice(key(c))} />
            <span className="stack" style={{ gap: 2 }}>
              <span>
                <strong>{kindLabel[c.kind]}</strong> <span className="mono">{c.interface}</span>{" "}
                <Badge tone={c.carrier ? (c.speedMbps >= 10_000 ? "good" : "info") : "warn"}>{speed(c.carrier ? c.speedMbps : 0)}</Badge>
              </span>
              {c.warning && <span className="small muted">{c.warning}</span>}
            </span>
          </label>
        ))}
      </fieldset>
      <div className="row" style={{ gap: 16, flexWrap: "wrap" }}>
        <Field label="This server's storage address" hint={`With the prefix, e.g. ${d.suggested || "10.77.0.21/24"}`}>
          {(id) => <TextInput id={id} value={address} className="input mono" onChange={(e) => setAddress(e.target.value)} />}
        </Field>
        {cand?.kind === "vlan" && (
          <Field label="VLAN" hint="Your switch must carry this VLAN on the port.">
            {(id) => <TextInput id={id} inputMode="numeric" value={vlan} onChange={(e) => setVlan(e.target.value)} />}
          </Field>
        )}
      </div>
      <Toggle
        label="Jumbo frames (MTU 9000)"
        description={
          jumboOK
            ? "Faster for big transfers. Turn it on only if every server's storage port and the switch support it."
            : "Not offered for this choice."
        }
        checked={jumbo && jumboOK}
        disabled={!jumboOK}
        onChange={setJumbo}
      />
      {problems.length > 0 && (
        <Alert tone="bad" title="Some settings need fixing">
          <ul>
            {problems.map((p) => (
              <li key={p}>{p}</li>
            ))}
          </ul>
        </Alert>
      )}
      {jobId ? (
        <JobProgress
          id={jobId}
          onDone={(job) => {
            void qc.invalidateQueries({ queryKey: storageKeys.network });
            void qc.invalidateQueries({ queryKey: ["network"] });
            if (job.state === "succeeded" && plan) onDone?.(plan);
          }}
        />
      ) : (
        <div className="row">
          <Button variant="primary" disabled={!plan || !address} busy={apply.isPending} onClick={() => plan && apply.mutate(plan)}>
            {cand?.kind === "lan" ? "Use the LAN" : "Set up the storage network"}
          </Button>
        </div>
      )}
    </div>
  );
}
