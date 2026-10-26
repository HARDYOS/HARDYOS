import type { Job, Share, ShareRule } from "@hardy/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, errorMessage, unwrap } from "../../api";
import { bytes } from "../../format";
import { useDataPools } from "../../hooks/queries";
import { EditIcon, FolderIcon, PlusIcon, TrashIcon } from "../../icons";
import { Alert, Badge, Button, Card, EmptyState, ErrorBox, Field, IconButton, Loading, PageHeader, Progress, Select, TextInput, Toggle } from "../../ui";
import { ConfirmDialog, Dialog } from "../../ui/Dialog";
import { toast } from "../../ui/toasts";
import { cleanName, deriveId, idProblem, nameProblem, type QuotaUnit, quotaBytes, quotaFields } from "./sharesRules";

export const useShares = () => useQuery({ queryKey: ["shares"], queryFn: () => unwrap(api.GET("/shares")).then((r) => r.shares), refetchInterval: 30_000 });

/** Waits for a job a request started; throws its error if it fails. */
async function finished(start: Promise<{ job: Job }>): Promise<Job> {
  const { job } = await start;
  for (;;) {
    const j = await unwrap(api.GET("/jobs/{id}", { params: { path: { id: job.id } } }));
    if (j.state === "succeeded") return j;
    if (j.state === "failed" || j.state === "cancelled") throw new Error(j.error || `${j.title}: ${j.state}`);
    await new Promise((r) => setTimeout(r, 500));
  }
}

const LEVEL_LABEL: Record<ShareRule["level"], string> = { read: "Read only", write: "Read and write", none: "No access" };

/** Control Panel > Shared Folders. Family members see the list; administrators change it. */
export function SharedFolders({ admin }: { admin: boolean }) {
  const shares = useShares();
  const pools = useDataPools(admin);
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<Share | null>(null);
  const [deleting, setDeleting] = useState<Share | null>(null);
  const qc = useQueryClient();
  const refresh = () => void qc.invalidateQueries({ queryKey: ["shares"] });

  if (shares.isPending) return <Loading />;
  if (shares.isError) return <ErrorBox error={shares.error} onRetry={() => shares.refetch()} />;
  const list = shares.data;
  const poolNames = pools.data?.map((p) => p.name) ?? [];

  return (
    <>
      <PageHeader
        title="Shared Folders"
        subtitle="Folders on your pools for the family's files: movies, photos, backups. Apps can be given them too."
        actions={
          admin && list.length > 0 ? (
            <Button variant="primary" onClick={() => setCreating(true)} disabled={poolNames.length === 0}>
              <PlusIcon size={16} /> New shared folder
            </Button>
          ) : undefined
        }
      />
      <Alert tone="info" title="Opening them from computers comes with file sharing">
        Shared folders are ready for apps now. Reaching them from Windows, Macs and phones (SMB, NFS, Time Machine) arrives with file sharing, and the
        access rules you set here apply then.
      </Alert>

      {admin && pools.isSuccess && poolNames.length === 0 && (
        <Alert tone="warn" title="No pool yet">
          Shared folders live on a storage pool. Create one in Storage first.
        </Alert>
      )}

      {list.length === 0 ? (
        admin && poolNames.length > 0 ? (
          <StarterCard pools={poolNames} onCustom={() => setCreating(true)} onDone={refresh} />
        ) : (
          <Card>
            <EmptyState icon={<FolderIcon size={30} />} title="No shared folders yet">
              {admin ? "Create a pool first, then come back to make the family's shared folders." : "An administrator hasn't made any shared folders yet."}
            </EmptyState>
          </Card>
        )
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Shared folder</th>
                {admin && <th>Pool</th>}
                <th>Used</th>
                {admin && <th>Who can use it</th>}
                {admin && (
                  <th className="actions">
                    <span className="sr-only">Actions</span>
                  </th>
                )}
              </tr>
            </thead>
            <tbody>
              {list.map((s) => (
                <tr key={s.id}>
                  <td>
                    <div className="row" style={{ flexWrap: "nowrap" }}>
                      <span style={{ color: "var(--hos-accent)" }}>
                        <FolderIcon size={22} />
                      </span>
                      <div>
                        <strong>{s.name}</strong>
                        <span className="cell-sub">{s.description || <span className="mono">{s.path || s.id}</span>}</span>
                        <div className="row" style={{ gap: 6, marginTop: 4 }}>
                          {!s.mounted && <Badge tone="warn">Not available</Badge>}
                          {s.recycle && <Badge tone="neutral">Recycle bin</Badge>}
                          {s.guest && <Badge tone="info">Guests can read</Badge>}
                        </div>
                      </div>
                    </div>
                  </td>
                  {admin && <td className="mono small">{s.pool}</td>}
                  <td style={{ minWidth: 160 }}>
                    <Usage share={s} />
                  </td>
                  {admin && (
                    <td className="small">
                      <AccessSummary share={s} />
                    </td>
                  )}
                  {admin && (
                    <td className="actions">
                      <IconButton label={`Edit ${s.name}`} onClick={() => setEditing(s)}>
                        <EditIcon size={16} />
                      </IconButton>
                      <IconButton label={`Delete ${s.name}`} onClick={() => setDeleting(s)}>
                        <TrashIcon size={16} />
                      </IconButton>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {creating && <ShareDialog pools={poolNames} onClose={() => setCreating(false)} onDone={refresh} />}
      {editing && <ShareDialog share={editing} pools={poolNames} onClose={() => setEditing(null)} onDone={refresh} />}
      {deleting && <DeleteShare share={deleting} onClose={() => setDeleting(null)} onDone={refresh} />}
    </>
  );
}

function Usage({ share }: { share: Share }) {
  if (!share.quotaBytes) return <span className="mono">{bytes(share.usedBytes)}</span>;
  const pct = (share.usedBytes / share.quotaBytes) * 100;
  return (
    <div className="stack" style={{ gap: 4 }}>
      <span className="small">
        <span className="mono">{bytes(share.usedBytes)}</span> <span className="muted">of</span> <span className="mono">{bytes(share.quotaBytes)}</span>
      </span>
      <Progress value={pct} tone={pct >= 90 ? "bad" : pct >= 75 ? "warn" : "accent"} label={`${share.name} quota used`} />
    </div>
  );
}

function principalLabel(r: ShareRule): string {
  return r.kind === "everyone" ? "Everyone" : r.name ?? "";
}

function AccessSummary({ share }: { share: Share }) {
  const rules = share.access.filter((r) => r.level !== "none");
  return (
    <div className="stack" style={{ gap: 4 }}>
      {rules.length === 0 ? (
        <span className="muted">Administrators only</span>
      ) : (
        <span>{rules.map((r) => `${principalLabel(r)} (${r.level === "write" ? "read and write" : "read"})`).join(", ")}</span>
      )}
      {share.apps.length > 0 && (
        <span className="muted">
          Apps: {share.apps.map((a) => a.app).join(", ")}
        </span>
      )}
    </div>
  );
}

// ---- starter set -------------------------------------------------------

function StarterCard({ pools, onCustom, onDone }: { pools: string[]; onCustom: () => void; onDone: () => void }) {
  const [media, setMedia] = useState(true);
  const [backups, setBackups] = useState(true);
  const [pool, setPool] = useState(pools[0] ?? "");
  const create = useMutation({
    mutationFn: () => finished(unwrap(api.POST("/shares/starter", { body: { pool, media, backups } }))),
    onSuccess: () => {
      toast("success", "The shared folders are ready");
      onDone();
    },
  });
  return (
    <Card title="Start with the usual folders">
      <div className="stack">
        <span className="small muted">Most homes start with these. You can rename them, set quotas and add more later.</span>
        <Toggle label="Media" description="With Movies, TV, Music and Photos folders inside, for Jellyfin, Plex or Immich." checked={media} onChange={setMedia} />
        <Toggle label="Backups" description="Somewhere for the family's computers and phones to back up to." checked={backups} onChange={setBackups} />
        {pools.length > 1 && (
          <Field label="Pool">
            {(id) => (
              <Select id={id} value={pool} onChange={(e) => setPool(e.target.value)}>
                {pools.map((p) => (
                  <option key={p} value={p}>
                    {p}
                  </option>
                ))}
              </Select>
            )}
          </Field>
        )}
        {create.isError && <Alert tone="bad">{errorMessage(create.error)}</Alert>}
        <div className="row">
          <Button variant="primary" disabled={!media && !backups} busy={create.isPending} onClick={() => create.mutate()}>
            Create {media && backups ? "both" : media ? "Media" : backups ? "Backups" : ""}
          </Button>
          <Button onClick={onCustom}>Make my own instead</Button>
        </div>
      </div>
    </Card>
  );
}

// ---- create and edit ---------------------------------------------------

type Option = { value: string; label: string; rule: Omit<ShareRule, "level"> };

const optionValue = (r: Omit<ShareRule, "level">) => `${r.kind}:${r.kind === "everyone" ? "" : (r.name ?? "").toLowerCase()}`;

/** Everyone, plus the domain's people and groups when there's a domain. */
function usePrincipals(): { options: Option[]; domain: boolean; loading: boolean } {
  const status = useQuery({ queryKey: ["domain"], queryFn: () => unwrap(api.GET("/domain")), staleTime: 60_000 });
  const provisioned = !!status.data?.provisioned && !!status.data.config;
  const nb = status.data?.config?.netbios ?? "";
  const users = useQuery({ queryKey: ["domain", "users"], queryFn: () => unwrap(api.GET("/domain/users")).then((r) => r.users), enabled: provisioned });
  const groups = useQuery({ queryKey: ["domain", "groups"], queryFn: () => unwrap(api.GET("/domain/groups")).then((r) => r.groups), enabled: provisioned });
  const options: Option[] = [{ value: "everyone:", label: "Everyone", rule: { kind: "everyone" } }];
  for (const g of groups.data ?? []) {
    if (g.builtin && g.name !== "Domain Users" && g.name !== "Domain Admins") continue;
    const rule = { kind: "group" as const, name: `${nb}\\${g.name}` };
    options.push({ value: optionValue(rule), label: `${g.name} (group)`, rule });
  }
  for (const u of users.data ?? []) {
    if (u.builtin) continue;
    const rule = { kind: "user" as const, name: `${nb}\\${u.username}` };
    options.push({ value: optionValue(rule), label: u.displayName ? `${u.displayName} (${u.username})` : u.username, rule });
  }
  return { options, domain: provisioned, loading: status.isPending || (provisioned && (users.isPending || groups.isPending)) };
}

function ShareDialog({ share, pools, onClose, onDone }: { share?: Share; pools: string[]; onClose: () => void; onDone: () => void }) {
  const editing = !!share;
  const q = quotaFields(share?.quotaBytes ?? 0);
  const [pool, setPool] = useState(share?.pool ?? pools[0] ?? "");
  const [name, setName] = useState(share?.name ?? "");
  const [id, setId] = useState("");
  const [description, setDescription] = useState(share?.description ?? "");
  const [quota, setQuota] = useState(q.value);
  const [unit, setUnit] = useState<QuotaUnit>(q.unit);
  const [recycle, setRecycle] = useState(share?.recycle ?? true);
  const [guest, setGuest] = useState(share?.guest ?? false);
  const [rules, setRules] = useState<ShareRule[]>(share?.access ?? []);
  const principals = usePrincipals();

  const nProblem = name ? nameProblem(name) : null;
  const derived = deriveId(cleanName(name));
  const needsId = !editing && name.trim() !== "" && !nProblem && derived === "";
  const iProblem = needsId && id ? idProblem(id) : null;
  const qBytes = quotaBytes(quota, unit);
  const qProblem = qBytes === null ? "Enter a number, or leave it empty for no quota." : qBytes > 0 && qBytes < 1e6 ? "At least 1 MB." : null;
  const ready = !!pool && name.trim() !== "" && !nProblem && !qProblem && (!needsId || (id !== "" && !iProblem));

  const options = [...principals.options];
  for (const r of rules) {
    if (!options.some((o) => o.value === optionValue(r))) options.push({ value: optionValue(r), label: principalLabel(r), rule: { kind: r.kind, name: r.name } });
  }
  const unused = options.filter((o) => !rules.some((r) => optionValue(r) === o.value));

  const save = useMutation({
    mutationFn: () => {
      const access = rules.map((r) => (r.kind === "everyone" ? { kind: r.kind, level: r.level } : r));
      if (share) {
        return finished(
          unwrap(
            api.PATCH("/shares/{id}", {
              params: { path: { id: share.id } },
              body: { name: cleanName(name), description: description.trim(), quotaBytes: qBytes ?? 0, recycle, guest, access },
            }),
          ),
        );
      }
      return finished(
        unwrap(
          api.POST("/shares", {
            body: { pool, name: cleanName(name), id: needsId ? id : undefined, description: description.trim() || undefined, quotaBytes: qBytes ?? 0, recycle, guest, access },
          }),
        ),
      );
    },
    onSuccess: () => {
      toast("success", editing ? `${cleanName(name)} is saved` : `${cleanName(name)} is ready`);
      onDone();
      onClose();
    },
  });

  return (
    <Dialog
      title={editing ? `Edit ${share.name}` : "New shared folder"}
      width={600}
      onClose={onClose}
      onSubmit={() => ready && save.mutate()}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" disabled={!ready} busy={save.isPending}>
            {editing ? "Save" : "Create"}
          </Button>
        </>
      }
    >
      <div className="stack">
        {!editing && (
          <Field label="Pool" hint={pools.length === 0 ? "Create a pool in Storage first." : "Where its files are kept. A shared folder can't move to another pool later."}>
            {(fid) => (
              <Select id={fid} value={pool} onChange={(e) => setPool(e.target.value)}>
                {pools.map((p) => (
                  <option key={p} value={p}>
                    {p}
                  </option>
                ))}
              </Select>
            )}
          </Field>
        )}
        <Field
          label="Name"
          error={nProblem}
          hint={
            editing ? undefined : derived ? (
              <>
                Its folder will be <span className="mono">{derived}</span>.
              </>
            ) : (
              "Like Media, Photos or Backups."
            )
          }
        >
          {(fid) => <TextInput id={fid} value={name} onChange={(e) => setName(e.target.value)} maxLength={60} placeholder="Photos" autoFocus />}
        </Field>
        {needsId && (
          <Field label="Folder id" error={iProblem} hint="The name has no letters a-z, so choose a short id for its folder: lowercase letters, digits and dashes.">
            {(fid) => <TextInput id={fid} className="input mono" value={id} onChange={(e) => setId(e.target.value.toLowerCase())} spellCheck={false} />}
          </Field>
        )}
        <Field label="Description" hint="Optional.">
          {(fid) => <TextInput id={fid} value={description} onChange={(e) => setDescription(e.target.value)} maxLength={200} />}
        </Field>
        <Field label="Quota" error={qProblem} hint="The most it may hold. Leave empty for no limit.">
          {(fid) => (
            <div className="row" style={{ flexWrap: "nowrap" }}>
              <TextInput id={fid} className="input mono" inputMode="decimal" value={quota} onChange={(e) => setQuota(e.target.value)} placeholder="No limit" style={{ flex: 1 }} />
              <Select aria-label="Quota unit" value={unit} onChange={(e) => setUnit(e.target.value as QuotaUnit)} style={{ width: 90 }}>
                <option value="GB">GB</option>
                <option value="TB">TB</option>
              </Select>
            </div>
          )}
        </Field>
        <Toggle label="Recycle bin" description="Files deleted over the network go to a recycle bin first (with file sharing)." checked={recycle} onChange={setRecycle} />
        <Toggle label="Guest access" description="People on your network can read it without signing in (with file sharing)." checked={guest} onChange={setGuest} />

        <div className="stack" style={{ gap: 8 }}>
          <strong className="small">Who can use it</strong>
          {!principals.domain && !principals.loading && (
            <span className="small muted">Set up a domain in Control Panel &gt; Domain to give family members' own accounts access.</span>
          )}
          {rules.length === 0 && <span className="small muted">Only administrators, until you add someone.</span>}
          {rules.map((r, i) => (
            <div key={optionValue(r)} className="row" style={{ flexWrap: "nowrap", gap: 8 }}>
              <Select
                aria-label={`Who, rule ${i + 1}`}
                value={optionValue(r)}
                onChange={(e) => {
                  const o = options.find((x) => x.value === e.target.value);
                  if (o) setRules(rules.map((x, j) => (j === i ? { ...o.rule, level: x.level } : x)));
                }}
                style={{ flex: 1 }}
              >
                {options
                  .filter((o) => o.value === optionValue(r) || unused.includes(o))
                  .map((o) => (
                    <option key={o.value} value={o.value}>
                      {o.label}
                    </option>
                  ))}
              </Select>
              <Select
                aria-label={`Access for ${principalLabel(r)}`}
                value={r.level}
                onChange={(e) => setRules(rules.map((x, j) => (j === i ? { ...x, level: e.target.value as ShareRule["level"] } : x)))}
                style={{ width: 170 }}
              >
                {(["read", "write", "none"] as const).map((l) => (
                  <option key={l} value={l}>
                    {LEVEL_LABEL[l]}
                  </option>
                ))}
              </Select>
              <IconButton label={`Remove ${principalLabel(r)}`} onClick={() => setRules(rules.filter((_, j) => j !== i))}>
                <TrashIcon size={16} />
              </IconButton>
            </div>
          ))}
          {unused.length > 0 && (
            <div>
              <Button size="sm" onClick={() => unused[0] && setRules([...rules, { ...unused[0].rule, level: "read" }])}>
                <PlusIcon size={14} /> Add someone
              </Button>
            </div>
          )}
        </div>
        {save.isError && <Alert tone="bad">{errorMessage(save.error)}</Alert>}
      </div>
    </Dialog>
  );
}

// ---- delete ------------------------------------------------------------

function DeleteShare({ share, onClose, onDone }: { share: Share; onClose: () => void; onDone: () => void }) {
  if (share.apps.length > 0) {
    return (
      <Dialog title={`Delete ${share.name}`} onClose={onClose} footer={<Button onClick={onClose}>OK</Button>}>
        <Alert tone="warn" title="Apps use this shared folder">
          {share.apps.map((a) => a.app).join(", ")} {share.apps.length === 1 ? "uses" : "use"} {share.name}. Take it away from{" "}
          {share.apps.length === 1 ? "that app" : "those apps"} in the App Store first.
        </Alert>
      </Dialog>
    );
  }
  return (
    <ConfirmDialog
      title={`Delete ${share.name}?`}
      confirmLabel="Delete it and its files"
      typeToConfirm={share.name}
      onClose={onClose}
      onConfirm={async () => {
        await finished(unwrap(api.DELETE("/shares/{id}", { params: { path: { id: share.id } }, body: { confirm: share.name } })));
        toast("success", `${share.name} is deleted`);
        onDone();
      }}
    >
      Every file in {share.name} ({bytes(share.usedBytes)}) and its snapshots are deleted for good. This can't be undone.
    </ConfirmDialog>
  );
}
