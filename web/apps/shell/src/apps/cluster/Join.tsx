import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { components } from "@hardy/api-client";
import { useState } from "react";
import { api, errorMessage, unwrap } from "../../api";
import { dateTime } from "../../format";
import { Alert, Button, Card, Field, PageHeader, Select, TextInput } from "../../ui";
import { JobProgress } from "../shared";
import type { ClusterStatus } from "../../cluster/scope";
import { StorageNetworkStep } from "./storage";

type Offer = components["schemas"]["ClusterJoinOffer"];

/** Outside a cluster: create one, or join one with a code from a member. */
export function CreateOrJoin() {
  const [mode, setMode] = useState<"create" | "join">("create");
  return (
    <div className="stack">
      <div className="row" role="tablist">
        <Button variant={mode === "create" ? "primary" : "ghost"} onClick={() => setMode("create")}>
          Create a cluster
        </Button>
        <Button variant={mode === "join" ? "primary" : "ghost"} onClick={() => setMode("join")}>
          Join a cluster
        </Button>
      </div>
      {mode === "create" ? (
        <>
          <CreateForm />
          <Card title="Storage network">
            <p className="muted small">iSCSI and NFS between the servers go over their own network: a dedicated port, a VLAN, or (not recommended) the LAN.</p>
            <StorageNetworkStep />
          </Card>
        </>
      ) : (
        <JoinWizard />
      )}
    </div>
  );
}

function CreateForm() {
  const [name, setName] = useState("");
  const [role, setRole] = useState<"storage" | "compute">("storage");
  const [subnet, setSubnet] = useState("10.77.0.0/24");
  const [job, setJob] = useState<string | null>(null);
  const qc = useQueryClient();
  const m = useMutation({
    mutationFn: () => unwrap(api.POST("/cluster", { body: { name, role, storageSubnet: subnet || undefined } })),
    onSuccess: (r) => setJob(r.job.id),
  });
  return (
    <Card title="Create a cluster">
      <div className="stack">
        <p className="muted small">
          This server becomes the cluster's first member. The NAS that holds the pool is the storage node; the others are compute servers.
        </p>
        <Field label="Cluster name">{(id) => <TextInput id={id} value={name} onChange={(e) => setName(e.target.value)} maxLength={64} />}</Field>
        <Field label="This server's role">
          {(id) => (
            <Select id={id} value={role} onChange={(e) => setRole(e.target.value as "storage" | "compute")}>
              <option value="storage">Storage (holds the pool)</option>
              <option value="compute">Compute (runs VMs and apps)</option>
            </Select>
          )}
        </Field>
        <Field label="Storage network" hint="The dedicated network for iSCSI and NFS (own port or VLAN). Leave empty to choose later.">
          {(id) => <TextInput id={id} value={subnet} onChange={(e) => setSubnet(e.target.value)} placeholder="10.77.0.0/24" />}
        </Field>
        {m.error && <Alert tone="bad">{errorMessage(m.error)}</Alert>}
        {job ? (
          <JobProgress id={job} onDone={() => qc.invalidateQueries({ queryKey: ["cluster"] })} />
        ) : (
          <div>
            <Button variant="primary" busy={m.isPending} disabled={!name.trim()} onClick={() => m.mutate()}>
              Create
            </Button>
          </div>
        )}
      </div>
    </Card>
  );
}

/** The join wizard: a member's address, its code, this server's role. */
function JoinWizard() {
  const [step, setStep] = useState(1);
  const [address, setAddress] = useState("");
  const [code, setCode] = useState("");
  const [role, setRole] = useState<"compute" | "storage">("compute");
  const [job, setJob] = useState<string | null>(null);
  const qc = useQueryClient();
  const m = useMutation({
    mutationFn: () => unwrap(api.POST("/cluster/join", { body: { address, code, role } })),
    onSuccess: (r) => setJob(r.job.id),
  });
  return (
    <Card title={`Join a cluster — step ${step} of 4`}>
      <div className="stack">
        {step === 1 && (
          <>
            <p className="muted small">On a member, open Cluster › Add server and make a code. It shows the member's addresses.</p>
            <Field label="Member's address" hint="Its LAN address (or NetBird address), like 192.168.1.105">
              {(id) => <TextInput id={id} value={address} onChange={(e) => setAddress(e.target.value)} />}
            </Field>
            <div>
              <Button variant="primary" disabled={!address.trim()} onClick={() => setStep(2)}>
                Next
              </Button>
            </div>
          </>
        )}
        {step === 2 && (
          <>
            <Field label="Join code" hint="Valid once, for 30 minutes">
              {(id) => <TextInput id={id} className="mono" value={code} onChange={(e) => setCode(e.target.value)} autoComplete="off" />}
            </Field>
            <Field label="This server's role">
              {(id) => (
                <Select id={id} value={role} onChange={(e) => setRole(e.target.value as "compute" | "storage")}>
                  <option value="compute">Compute (runs VMs and apps)</option>
                  <option value="storage">Storage (holds the pool)</option>
                </Select>
              )}
            </Field>
            <div className="row">
              <Button onClick={() => setStep(1)}>Back</Button>
              <Button variant="primary" disabled={code.replace(/[-\s]/g, "").length < 26} onClick={() => setStep(3)}>
                Next
              </Button>
            </div>
          </>
        )}
        {step === 3 && (
          <>
            <p className="muted small">
              This server's address on the storage network (iSCSI and NFS from the storage server). It can also be set later in Cluster › Storage.
            </p>
            <StorageNetworkStep onDone={() => setStep(4)} />
            <div className="row">
              <Button onClick={() => setStep(2)}>Back</Button>
              <Button onClick={() => setStep(4)}>Next</Button>
            </div>
          </>
        )}
        {step === 4 && (
          <>
            <p>
              Join through <strong>{address}</strong> as a <strong>{role}</strong> server. The two servers prove the code to each other; this server keeps
              its own pools and apps.
            </p>
            {m.error && <Alert tone="bad">{errorMessage(m.error)}</Alert>}
            {job ? (
              <JobProgress id={job} onDone={() => qc.invalidateQueries({ queryKey: ["cluster"] })} />
            ) : (
              <div className="row">
                <Button onClick={() => setStep(3)}>Back</Button>
                <Button variant="primary" busy={m.isPending} onClick={() => m.mutate()}>
                  Join
                </Button>
              </div>
            )}
          </>
        )}
      </div>
    </Card>
  );
}

/** In a cluster: make a join code for a new server. */
export function AddServer({ st }: { st: ClusterStatus }) {
  const [role, setRole] = useState<"compute" | "storage">("compute");
  const [offer, setOffer] = useState<Offer | null>(null);
  const qc = useQueryClient();
  const codes = useQuery({ queryKey: ["cluster", "codes"], queryFn: () => unwrap(api.GET("/cluster/join-codes")) });
  const make = useMutation({
    mutationFn: () => unwrap(api.POST("/cluster/join-codes", { body: { role } })),
    onSuccess: (o) => {
      setOffer(o);
      void qc.invalidateQueries({ queryKey: ["cluster", "codes"] });
    },
  });
  const cancel = useMutation({
    mutationFn: (id: string) => unwrap(api.DELETE("/cluster/join-codes/{id}", { params: { path: { id } } })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["cluster", "codes"] }),
  });
  const hasStorage = st.nodes.some((n) => n.role === "storage");
  return (
    <div className="stack">
      <PageHeader title="Add a server" subtitle="Make a one-time code here, then open Cluster › Join a cluster on the new server." />
      <Card>
        <div className="stack">
          <Field label="The new server's role">
            {(id) => (
              <Select id={id} value={role} onChange={(e) => setRole(e.target.value as "compute" | "storage")}>
                <option value="compute">Compute</option>
                {!hasStorage && <option value="storage">Storage</option>}
              </Select>
            )}
          </Field>
          <div>
            <Button variant="primary" busy={make.isPending} onClick={() => make.mutate()}>
              Make a join code
            </Button>
          </div>
          {make.error && <Alert tone="bad">{errorMessage(make.error)}</Alert>}
          {offer && (
            <div className="stack">
              <div className="cluster-code">{offer.code}</div>
              <p className="small">
                Address{offer.addresses.length > 1 ? "es" : ""}: <span className="mono">{offer.addresses.join(", ")}</span> · valid until{" "}
                {dateTime(offer.expires)}. It is shown only now and works once.
              </p>
            </div>
          )}
        </div>
      </Card>
      <Card title="Open codes">
        {codes.data && codes.data.length > 0 ? (
          <ul className="stack">
            {codes.data.map((c) => (
              <li key={c.id} className="row row--between">
                <span>
                  {c.role} · until {dateTime(c.expires)} · by {c.createdBy}
                  {c.failures > 0 ? ` · ${c.failures} wrong tries` : ""}
                </span>
                <Button size="sm" variant="ghost" onClick={() => cancel.mutate(c.id)}>
                  Cancel
                </Button>
              </li>
            ))}
          </ul>
        ) : (
          <p className="muted small">None.</p>
        )}
      </Card>
    </div>
  );
}
