import type { AppPlan, CustomAppRequest } from "@hardy/api-client";
import { useState } from "react";
import { ApiFailure, api, errorMessage, unwrap } from "../../api";
import { PlusIcon, TrashIcon } from "../../icons";
import { Alert, Button, Field, PageHeader, TextInput } from "../../ui";

interface PortRow {
  label: string;
  name: string;
  port: string;
}
interface FolderRow {
  path: string;
  owner: string;
}

/** An app id from its name: "My Wiki" -> "my-wiki". */
export function idFromName(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .replace(/^[^a-z]+/, "")
    .slice(0, 32)
    .replace(/-+$/, "");
}

const SAMPLE = `services:
  web:
    image: traefik/whoami:latest
    ports:
      - "\${HARDY_PORT_WEB}:80"
    volumes:
      - \${HARDY_APP_DATA}/config:/config
    environment:
      TZ: \${HARDY_TZ}
`;

/** App Store › Create an app: a custom app from a pasted Compose file. */
export function CreateApp({ onPlanned }: { onPlanned: (plan: AppPlan) => void }) {
  const [name, setName] = useState("");
  const [id, setId] = useState("");
  const [idTouched, setIdTouched] = useState(false);
  const [compose, setCompose] = useState("");
  const [ports, setPorts] = useState<PortRow[]>([{ label: "Website", name: "WEB", port: "8080" }]);
  const [web, setWeb] = useState("WEB");
  const [folders, setFolders] = useState<FolderRow[]>([]);
  const [busy, setBusy] = useState(false);
  const [problems, setProblems] = useState<string[]>([]);
  const appId = idTouched ? id : idFromName(name);

  const portRowProblem = (p: PortRow) => {
    const n = Number(p.port);
    if (!/^[A-Z][A-Z0-9_]{0,23}$/.test(p.name)) return "Names use capital letters, digits and _";
    if (!Number.isInteger(n) || n < 1024 || n > 65535) return "Ports from 1024 to 65535";
    if (!p.label.trim()) return "Give it a label";
    return null;
  };
  const ready = name.trim() !== "" && /^[a-z][a-z0-9-]{0,30}[a-z0-9]$/.test(appId) && compose.trim() !== "" && ports.every((p) => !portRowProblem(p));

  async function submit() {
    if (!ready) return;
    setBusy(true);
    setProblems([]);
    const body: CustomAppRequest = {
      id: appId,
      name: name.trim(),
      compose,
      ports: ports.map((p) => ({ name: p.name, label: p.label.trim(), default: Number(p.port) })),
      webPort: ports.some((p) => p.name === web) ? web : undefined,
      folders: folders.filter((f) => f.path.trim()).map((f) => ({ path: f.path.trim(), owner: f.owner.trim() || undefined })),
    };
    try {
      onPlanned(await unwrap(api.POST("/apps/custom", { body })));
    } catch (err) {
      setProblems(err instanceof ApiFailure && err.details.length > 0 ? err.details : [errorMessage(err)]);
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <PageHeader title="Create an app" subtitle="Run your own Docker Compose app. It's sandboxed like an uploaded package." />
      <form
        className="stack"
        onSubmit={(e) => {
          e.preventDefault();
          void submit();
        }}
      >
        <div className="grid-2">
          <Field label="Name">{(fid) => <TextInput id={fid} value={name} onChange={(e) => setName(e.target.value)} placeholder="My wiki" />}</Field>
          <Field label="App id" hint="Lowercase letters, digits and dashes; names its dataset">
            {(fid) => (
              <TextInput
                id={fid}
                className="input mono"
                value={appId}
                onChange={(e) => {
                  setIdTouched(true);
                  setId(e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, ""));
                }}
              />
            )}
          </Field>
        </div>
        <Field
          label="Compose file"
          hint={
            <>
              Publish each port below as <span className="mono">{"${HARDY_PORT_<NAME>}"}</span> and keep data under{" "}
              <span className="mono">{"${HARDY_APP_DATA}"}</span>. <button type="button" className="link-button" onClick={() => setCompose(SAMPLE)}>Use an example</button>
            </>
          }
        >
          {(fid) => <textarea id={fid} className="input mono compose-input" rows={14} spellCheck={false} value={compose} onChange={(e) => setCompose(e.target.value)} />}
        </Field>

        <section className="install__section" aria-label="Ports">
          <h3>Ports</h3>
          {ports.map((p, i) => {
            const set = (patch: Partial<PortRow>) => setPorts(ports.map((x, j) => (j === i ? { ...x, ...patch } : x)));
            return (
              <div key={i} className="custom-row">
                <TextInput aria-label={`Port ${i + 1} label`} value={p.label} onChange={(e) => set({ label: e.target.value })} placeholder="Website" />
                <TextInput aria-label={`Port ${i + 1} name`} className="input mono" value={p.name} onChange={(e) => set({ name: e.target.value.toUpperCase().replace(/[^A-Z0-9_]/g, "") })} />
                <TextInput aria-label={`Port ${i + 1} number`} className="input mono" inputMode="numeric" value={p.port} onChange={(e) => set({ port: e.target.value.replace(/[^0-9]/g, "") })} />
                <label className="small custom-row__web">
                  <input type="radio" name="webport" checked={web === p.name} onChange={() => setWeb(p.name)} /> Web page
                </label>
                <Button size="sm" variant="ghost" aria-label={`Remove port ${i + 1}`} onClick={() => setPorts(ports.filter((_, j) => j !== i))}>
                  <TrashIcon size={13} />
                </Button>
                {portRowProblem(p) && <span className="field__error custom-row__error">{portRowProblem(p)}</span>}
              </div>
            );
          })}
          <div className="row">
            <Button size="sm" onClick={() => setPorts([...ports, { label: "", name: `PORT${ports.length + 1}`, port: "" }])}>
              <PlusIcon size={13} /> Add a port
            </Button>
          </div>
        </section>

        <section className="install__section" aria-label="Folders">
          <h3>Data folders</h3>
          <p className="small muted">Created inside the app's data folder before it starts. Give an owner (uid:gid) if its containers don't run as root.</p>
          {folders.map((f, i) => (
            <div key={i} className="custom-row">
              <TextInput aria-label={`Folder ${i + 1}`} className="input mono" value={f.path} placeholder="config" onChange={(e) => setFolders(folders.map((x, j) => (j === i ? { ...x, path: e.target.value } : x)))} />
              <TextInput aria-label={`Folder ${i + 1} owner`} className="input mono" value={f.owner} placeholder="1000:1000" onChange={(e) => setFolders(folders.map((x, j) => (j === i ? { ...x, owner: e.target.value } : x)))} />
              <Button size="sm" variant="ghost" aria-label={`Remove folder ${i + 1}`} onClick={() => setFolders(folders.filter((_, j) => j !== i))}>
                <TrashIcon size={13} />
              </Button>
            </div>
          ))}
          <div className="row">
            <Button size="sm" onClick={() => setFolders([...folders, { path: "", owner: "" }])}>
              <PlusIcon size={13} /> Add a folder
            </Button>
          </div>
        </section>

        {problems.length > 0 && (
          <Alert tone="bad" title="Can't create it yet">
            <ul className="install__problems">
              {problems.map((p) => (
                <li key={p}>{p}</li>
              ))}
            </ul>
          </Alert>
        )}
        <div className="row">
          <Button type="submit" variant="primary" disabled={!ready} busy={busy}>
            Continue to install
          </Button>
        </div>
      </form>
    </>
  );
}
