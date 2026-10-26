import type { AppCatalog, AppPackageRef } from "@hardy/api-client";
import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ApiFailure, api, errorMessage, unwrap } from "../../api";
import { relativeTime } from "../../format";
import { AlertIcon, PlusIcon, RefreshIcon, TrashIcon } from "../../icons";
import { Alert, Badge, Button, EmptyState, ErrorBox, Field, Loading, PageHeader, TextInput } from "../../ui";
import { ConfirmDialog } from "../../ui/Dialog";
import { toast } from "../../ui/toasts";
import { AppIcon, useImportedCatalogs } from "./common";

/** Discover's sections for imported catalogs. */
export function ImportedSections({ installed, onInstall, disabled }: { installed: Map<string, string>; onInstall: (ref: AppPackageRef) => void; disabled: boolean }) {
  const q = useImportedCatalogs(true);
  if (q.isPending || q.isError) return null;
  return (
    <>
      {q.data
        .filter((c) => c.apps.length > 0)
        .map((c) => (
          <section key={c.id} className="stack" aria-label={c.name}>
            <div className="row" style={{ gap: 8 }}>
              <h2 className="card__title">{c.name}</h2>
              <Badge tone="warn">Third-party</Badge>
            </div>
            <p className="small muted" style={{ margin: 0 }}>
              Not checked by HardyOS. These apps are sandboxed: anything extra they ask for has to be allowed one by one.
            </p>
            <div className="app-grid">
              {c.apps.map((a) => (
                <article key={a.sha256} className="app-card" aria-label={a.name}>
                  <header className="app-card__head">
                    <AppIcon src={a.icon} name={a.name} />
                    <div className="app-card__title">
                      <h3>{a.name}</h3>
                      <span className="small muted">
                        <span className="mono">{a.version}</span> · {c.name}
                      </span>
                    </div>
                    {installed.has(a.id) ? <Badge tone="good">Installed</Badge> : <Badge tone="warn">Third-party</Badge>}
                  </header>
                  {a.summary && <p className="app-card__summary">{a.summary}</p>}
                  <footer className="app-card__actions">
                    <Button size="sm" variant={installed.has(a.id) ? "secondary" : "primary"} disabled={disabled} onClick={() => onInstall({ source: "imported", ref: a.sha256, catalogId: c.id })}>
                      {installed.has(a.id) ? "Reinstall…" : "Install"}
                    </Button>
                  </footer>
                </article>
              ))}
            </div>
          </section>
        ))}
    </>
  );
}

/** App Store › Catalogs: import, refresh and remove third-party catalogs. */
export function CatalogsPage() {
  const qc = useQueryClient();
  const q = useImportedCatalogs(true);
  const [url, setUrl] = useState("");
  const [localNetwork, setLocalNetwork] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [problems, setProblems] = useState<string[]>([]);
  const [removing, setRemoving] = useState<AppCatalog | null>(null);
  const urlOk = /^https:\/\/[^\s/]+\/\S*$/.test(url.trim());

  async function importUrl(u: string, key: string) {
    setBusy(key);
    setProblems([]);
    try {
      // A refresh keeps the catalog's "On my network" setting.
      const c = await unwrap(api.POST("/apps/catalogs", { body: key === "add" ? { url: u, localNetwork } : { url: u } }));
      await qc.invalidateQueries({ queryKey: ["apps", "catalogs"] });
      toast("success", key === "add" ? `Imported ${c.name}` : `Refreshed ${c.name}`, `${c.apps.length} apps`);
      if (key === "add") {
        setUrl("");
        setLocalNetwork(false);
      }
    } catch (err) {
      setProblems(err instanceof ApiFailure && err.details.length > 0 ? err.details : [errorMessage(err)]);
    } finally {
      setBusy(null);
    }
  }

  return (
    <>
      <PageHeader title="Catalogs" subtitle="Add other people's app catalogs. Their apps show in Discover, labelled Third-party." />
      <div className="stack">
        <Alert tone="warn" title="Only add catalogs you trust">
          HardyOS doesn't check third-party apps. They run sandboxed, and each extra permission one asks for (the host network, the GPU, devices) has to be
          ticked by an administrator when it's installed.
        </Alert>
        <form
          className="card stack"
          onSubmit={(e) => {
            e.preventDefault();
            if (urlOk) void importUrl(url.trim(), "add");
          }}
        >
          <Field label="Catalog address" hint="An https:// address of the catalog's index.json">
            {(fid) => (
              <TextInput id={fid} className="input mono" placeholder="https://example.com/hardyos/index.json" value={url} onChange={(e) => setUrl(e.target.value)} spellCheck={false} />
            )}
          </Field>
          <div className="grant-list">
            <label>
              <input type="checkbox" checked={localNetwork} onChange={(e) => setLocalNetwork(e.target.checked)} />
              <span>
                On my network: the catalog is on this server or another device at home. HardyOS won't fetch catalogs from local addresses (like 192.168.x.x)
                unless this is ticked, so a catalog can't send it to your router or other devices.
              </span>
            </label>
          </div>
          {problems.length > 0 && <Alert tone="bad">{problems.join(" ")}</Alert>}
          <div className="row">
            <Button type="submit" variant="primary" disabled={!urlOk} busy={busy === "add"}>
              <PlusIcon size={14} /> Import catalog
            </Button>
          </div>
        </form>
        {q.isPending ? (
          <Loading />
        ) : q.isError ? (
          <ErrorBox error={q.error} onRetry={() => q.refetch()} />
        ) : q.data.length === 0 ? (
          <EmptyState title="No catalogs imported">Paste a catalog's address above to add its apps to Discover.</EmptyState>
        ) : (
          <div className="table-wrap card">
            <table className="table">
              <thead>
                <tr>
                  <th>Catalog</th>
                  <th>Apps</th>
                  <th>Checked</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {q.data.map((c) => (
                  <tr key={c.id}>
                    <td>
                      <div className="row" style={{ gap: 6 }}>
                        {c.name}
                        {c.localNetwork && <Badge tone="neutral">On my network</Badge>}
                      </div>
                      <div className="mono small muted">{c.url}</div>
                      {c.lastError && (
                        <div className="small catalog-note">
                          <AlertIcon size={12} /> {c.lastError}
                        </div>
                      )}
                    </td>
                    <td className="mono">{c.apps.length}</td>
                    <td>{c.fetchedAt ? relativeTime(c.fetchedAt) : "never"}</td>
                    <td className="actions">
                      <Button size="sm" variant="ghost" busy={busy === `r${c.id}`} onClick={() => importUrl(c.url, `r${c.id}`)} aria-label={`Refresh ${c.name}`}>
                        <RefreshIcon size={14} />
                      </Button>
                      <Button size="sm" variant="ghost" onClick={() => setRemoving(c)} aria-label={`Remove ${c.name}`}>
                        <TrashIcon size={14} />
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
      {removing && (
        <ConfirmDialog
          title={`Remove ${removing.name}?`}
          confirmLabel="Remove catalog"
          onClose={() => setRemoving(null)}
          onConfirm={async () => {
            await unwrap(api.DELETE("/apps/catalogs", { body: { id: removing.id } }));
            await qc.invalidateQueries({ queryKey: ["apps", "catalogs"] });
          }}
        >
          Its apps disappear from Discover. Apps already installed from it keep running, but won't get updates from it.
        </ConfirmDialog>
      )}
    </>
  );
}
