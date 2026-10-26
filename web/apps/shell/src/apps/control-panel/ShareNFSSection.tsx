import type { Share, ShareServices } from "@hardy/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type KeyboardEvent, useState } from "react";
import { api, errorMessage, unwrap } from "../../api";
import { PlusIcon, TrashIcon } from "../../icons";
import { Alert, Badge, Button, IconButton, Select, TextInput, Toggle } from "../../ui";
import { toast } from "../../ui/toasts";
import { mountCommands, nfsClientProblem } from "./nfsRules";
import { DEFAULT_SERVICES, saveServices } from "./shareServices";

type Client = ShareServices["nfs"]["clients"][number];

/** Shared folder dialog: NFS on/off, which computers may mount it, and how. */
export function ShareNFSSection({ share }: { share?: Share }) {
  if (!share) {
    return (
      <div className="stack" style={{ gap: 6 }}>
        <strong className="small">NFS (Linux and Unix computers)</strong>
        <span className="small muted">Off for new folders. Turn it on here once the folder is made.</span>
      </div>
    );
  }
  return <NFS share={share} />;
}

function NFS({ share }: { share: Share }) {
  const qc = useQueryClient();
  const saved = share.services?.nfs ?? DEFAULT_SERVICES.nfs;
  const [base, setBase] = useState(saved);
  const [enabled, setEnabled] = useState(saved.enabled);
  const [clients, setClients] = useState<Client[]>(saved.clients);
  const info = useQuery({
    queryKey: ["shares", share.id, "nfs"],
    queryFn: () => unwrap(api.GET("/shares/{id}/nfs", { params: { path: { id: share.id } } })),
    enabled: base.enabled,
  });

  const problems = clients.map((c) => nfsClientProblem(c.client));
  const dupes = clients.map((c, i) => clients.findIndex((o) => o.client.trim() === c.client.trim()) !== i);
  const changed = enabled !== base.enabled || JSON.stringify(clients) !== JSON.stringify(base.clients);
  const ready = problems.every((p) => !p) && !dupes.some(Boolean) && (!enabled || clients.length > 0) && clients.length <= 32;

  const save = useMutation({
    mutationFn: () => saveServices(share.id, (s) => ({ ...s, nfs: { enabled, clients: clients.map((c) => ({ client: c.client.trim(), access: c.access })) } })),
    onSuccess: (sh) => {
      toast("success", enabled ? `${share.name} is shared over NFS` : "NFS settings saved");
      const n = sh.services.nfs;
      setBase(n);
      setClients(n.clients);
      void qc.invalidateQueries({ queryKey: ["shares"] });
    },
  });
  const noEnter = (e: KeyboardEvent) => {
    if (e.key === "Enter") e.preventDefault();
  };

  const host = typeof window !== "undefined" ? window.location.hostname : "hardyos";
  const path = info.data?.path || share.path;
  const cmds = mountCommands(host, path, share.id);

  return (
    <div className="stack" style={{ gap: 10 }}>
      <strong className="small">NFS (Linux and Unix computers)</strong>
      <Toggle
        label="Share over NFS"
        description="Only the computers and networks listed below can mount it. Each one either reads, or reads and writes."
        checked={enabled}
        onChange={(v) => {
          setEnabled(v);
          if (v && clients.length === 0) setClients([{ client: "", access: "read" }]);
        }}
      />
      {(enabled || clients.length > 0) && (
        <div className="stack" style={{ gap: 8 }}>
          {clients.map((c, i) => (
            <div key={i} className="stack" style={{ gap: 2 }}>
              <div className="row" style={{ flexWrap: "nowrap", gap: 8 }}>
                <TextInput
                  aria-label={`Computer or network ${i + 1}`}
                  className="input mono"
                  value={c.client}
                  placeholder="192.168.1.0/24"
                  spellCheck={false}
                  onKeyDown={noEnter}
                  onChange={(e) => setClients(clients.map((x, j) => (j === i ? { ...x, client: e.target.value } : x)))}
                  style={{ flex: 1 }}
                />
                <Select
                  aria-label={`Access for computer or network ${i + 1}`}
                  value={c.access}
                  onChange={(e) => setClients(clients.map((x, j) => (j === i ? { ...x, access: e.target.value as Client["access"] } : x)))}
                  style={{ width: 160 }}
                >
                  <option value="read">Read only</option>
                  <option value="write">Read and write</option>
                </Select>
                <IconButton label={`Remove ${c.client || `computer ${i + 1}`}`} onClick={() => setClients(clients.filter((_, j) => j !== i))}>
                  <TrashIcon size={16} />
                </IconButton>
              </div>
              {c.client.trim() !== "" && (problems[i] || dupes[i]) && (
                <span className="field__error" role="alert">
                  {dupes[i] ? `${c.client.trim()} is listed twice.` : problems[i]}
                </span>
              )}
            </div>
          ))}
          <div>
            <Button size="sm" disabled={clients.length >= 32} onClick={() => setClients([...clients, { client: "", access: "read" }])}>
              <PlusIcon size={14} /> Add a computer or network
            </Button>
          </div>
          <span className="small muted">
            An address (192.168.1.50, fd00::50) or a network (192.168.1.0/24). When a computer is in more than one, its own address wins, then the smallest
            network.
          </span>
        </div>
      )}
      {changed && (
        <div className="row">
          <Button size="sm" variant="primary" disabled={!ready} busy={save.isPending} onClick={() => save.mutate()}>
            Save NFS settings
          </Button>
          <Button
            size="sm"
            onClick={() => {
              setEnabled(base.enabled);
              setClients(base.clients);
            }}
          >
            Undo
          </Button>
        </div>
      )}
      {save.isError && <Alert tone="bad">{errorMessage(save.error)}</Alert>}

      {base.enabled && !changed && (
        <div className="stack" style={{ gap: 8 }}>
          <div className="row" style={{ gap: 6 }}>
            {info.data && (info.data.running ? <Badge tone="good">NFS server running</Badge> : <Badge tone="warn">NFS server starting</Badge>)}
            {info.data && info.data.uid > 0 && (
              <Badge tone="neutral">
                acts as user <span className="mono">{info.data.uid}</span>
              </Badge>
            )}
          </div>
          {info.data?.problem && <Alert tone="warn">{info.data.problem}</Alert>}
          <span className="small muted">
            Every computer listed acts as this folder's own NFS user, whatever user it says it is (root included), so files they make belong to that user and
            read-only computers can't change anything.
          </span>
          <Command label="Linux" text={cmds.linux} />
          <Command label="Linux, mounted at every start (/etc/fstab)" text={cmds.fstab} />
          <Command label="macOS (Terminal)" text={cmds.mac} />
          <Command label="macOS Finder: Go › Connect to Server" text={cmds.finder} />
        </div>
      )}
    </div>
  );
}

function Command({ label, text }: { label: string; text: string }) {
  return (
    <div className="stack" style={{ gap: 4 }}>
      <div className="row" style={{ justifyContent: "space-between" }}>
        <span className="small">{label}</span>
        <Button
          size="sm"
          variant="ghost"
          onClick={() => {
            void navigator.clipboard?.writeText(text).then(
              () => toast("success", "Copied"),
              () => undefined,
            );
          }}
        >
          Copy
        </Button>
      </div>
      <pre className="log-view" aria-label={label}>
        {text}
      </pre>
    </div>
  );
}
