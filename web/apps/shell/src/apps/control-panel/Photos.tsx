import type { AppPrincipal, PhotosLibrary, PhotosSettings, PhotosView, User } from "@hardy/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { api, errorMessage, unwrap } from "../../api";
import { relativeTime } from "../../format";
import { useJob } from "../../hooks/queries";
import { PhotoIcon, PlusIcon, RefreshIcon, TrashIcon } from "../../icons";
import { useShell } from "../../shell";
import { Alert, Badge, Button, Card, EmptyState, ErrorBox, Field, IconButton, Loading, PageHeader, Select, TextInput, Toggle } from "../../ui";
import { ConfirmDialog } from "../../ui/Dialog";
import { toast } from "../../ui/toasts";
import { libraryProblems, mlLabel, shareLabel } from "./photosRules";

const usePhotos = () =>
  useQuery({ queryKey: ["photos"], queryFn: () => unwrap(api.GET("/photos/settings")), refetchInterval: (q) => (q.state.data?.running ? 3_000 : false) });

/** Control Panel > Photos: Immich as the desktop's Photos (docs/photos.md). */
export function Photos() {
  const q = usePhotos();
  const qc = useQueryClient();
  const shell = useShell();
  const users = useQuery({ queryKey: ["users"], queryFn: () => unwrap(api.GET("/users")), staleTime: 60_000 });
  const [draft, setDraft] = useState<PhotosSettings | null>(null);
  const [jobId, setJobId] = useState<string | null>(null);
  const [apiKey, setApiKey] = useState("");
  const [confirmPublish, setConfirmPublish] = useState(false);
  const job = useJob(jobId);
  const running = !!job.data && (job.data.state === "queued" || job.data.state === "running");

  useEffect(() => {
    if (job.data && !running) void qc.invalidateQueries({ queryKey: ["photos"] });
  }, [job.data, running, qc]);

  const started = (r: { job: { id: string } }) => {
    setJobId(r.job.id);
    void qc.invalidateQueries({ queryKey: ["photos"] });
  };
  const save = useMutation({
    mutationFn: (s: PhotosSettings) => unwrap(api.PUT("/photos/settings", { body: s })),
    onSuccess: (r) => {
      setDraft(null);
      started(r);
    },
  });
  const sync = useMutation({ mutationFn: () => unwrap(api.POST("/photos/sync")), onSuccess: started });
  const link = useMutation({
    mutationFn: (key: string) => unwrap(api.POST("/photos/link", { body: { apiKey: key } })),
    onSuccess: (r) => {
      setApiKey("");
      started(r);
    },
  });

  if (q.isPending) return <Loading />;
  if (q.isError) return <ErrorBox error={q.error} onRetry={() => q.refetch()} />;
  const v: PhotosView = q.data;
  const st = v.status;
  const set: PhotosSettings = draft ?? v.settings;
  const edit = (p: Partial<PhotosSettings>) => setDraft({ ...set, ...p });
  const busy = running || v.running;
  const given = new Set(v.shares.filter((s) => s.share).map((s) => s.name));
  const problems = libraryProblems(set);

  const header = (
    <PageHeader
      title="Photos"
      subtitle="Immich backs up everyone's phones and shows their photos on the desktop. HardyOS sets it up: sign-in with HardyOS, a library per person, the family library and the photos already on the server."
      actions={
        <div className="row" style={{ gap: 8 }}>
          <Button onClick={() => sync.mutate()} busy={sync.isPending || busy} disabled={!st?.installed}>
            <RefreshIcon size={14} /> Apply now
          </Button>
          <Button variant="primary" disabled={!draft || problems.length > 0} busy={save.isPending || busy} onClick={() => save.mutate(set)}>
            Save and apply
          </Button>
        </div>
      }
    />
  );

  if (st && !st.installed) {
    return (
      <>
        {header}
        <EmptyState
          icon={<PhotoIcon size={28} />}
          title="Immich isn't installed"
          action={
            <Button variant="primary" onClick={() => shell.openApp("os.hardy.store")}>
              Open the App Store
            </Button>
          }
        >
          Install Immich from the App Store (Discover). Give it an empty shared folder of its own for the photos, and, if you like, the folders with photos you already have and a family folder.
        </EmptyState>
      </>
    );
  }

  return (
    <>
      {header}
      {[save.error, sync.error, link.error].filter(Boolean).map((e, i) => (
        <Alert key={i} tone="bad" title={errorMessage(e)} />
      ))}
      {job.data?.state === "failed" && <Alert tone="bad" title="Setting Immich up failed">{job.data.error}</Alert>}
      {st?.problem && !st.needsLink && <Alert tone={st.catalog ? "bad" : "warn"} title={st.problem} />}
      {problems.map((p) => (
        <Alert key={p} tone="warn" title={p} />
      ))}

      {st?.needsLink && (
        <Card title="Link Immich">
          <div className="stack">
            <p className="small muted">
              This Immich was set up before Photos and already has an administrator. In Immich, as that administrator, open Account Settings › API Keys, make a key with all permissions, and paste it here. HardyOS keeps it sealed and uses it to set Immich up.
            </p>
            <Field label="Immich API key">
              {(id) => <TextInput id={id} type="password" value={apiKey} onChange={(e) => setApiKey(e.target.value)} autoComplete="off" spellCheck={false} />}
            </Field>
            <div>
              <Button variant="primary" disabled={apiKey.trim().length < 16} busy={link.isPending} onClick={() => link.mutate(apiKey.trim())}>
                Link
              </Button>
            </div>
          </div>
        </Card>
      )}

      <Card
        title="Sign-in"
        actions={st ? <Badge tone={st.sso.active ? "good" : set.sso ? "warn" : "neutral"}>{st.sso.active ? "With HardyOS" : "Immich passwords"}</Badge> : undefined}
      >
        <div className="stack">
          <Toggle
            label="Sign in with HardyOS"
            description="Everyone uses their HardyOS account in Immich, on the web and in the phone app. Immich makes each person's account at their first sign-in; HardyOS administrators are Immich administrators."
            checked={set.sso}
            onChange={(on) => edit({ sso: on })}
          />
          {set.sso && (
            <>
              <Toggle label="Also allow Immich passwords" description="Keep Immich's own e-mail and password sign-in next to HardyOS's." checked={set.passwordLogin} onChange={(on) => edit({ passwordLogin: on })} />
              <Toggle label="Go straight to HardyOS's sign-in" description="Immich's sign-in page opens HardyOS's at once." checked={set.autoLaunch} onChange={(on) => edit({ autoLaunch: on })} />
            </>
          )}
          {st?.sso.why && <Alert tone="warn" title={st.sso.why} />}
          {st?.sso.active && (
            <div className="small muted">
              Client <span className="mono">{st.sso.clientId}</span> at <span className="mono">{st.sso.issuer}</span>; redirect addresses{" "}
              {st.sso.redirectUris.map((u) => (
                <span key={u} className="mono" style={{ display: "block" }}>
                  {u}
                </span>
              ))}
            </div>
          )}
          <Field label="Storage limit for new people (GB, 0 for none)">
            {(id) => (
              <TextInput id={id} type="number" min={0} value={set.defaultQuotaGiB} onChange={(e) => edit({ defaultQuotaGiB: Math.max(0, Number(e.target.value) || 0) })} />
            )}
          </Field>
        </div>
      </Card>

      <Card title="Phones" actions={st?.phoneReady ? <Badge tone="good">Ready from anywhere</Badge> : undefined}>
        <div className="stack">
          {st?.publishedUrl ? (
            <p className="small">
              In the Immich app, use the server address <span className="mono">{st.publishedUrl}</span>
              {st.sso.active ? " and Sign in with HardyOS." : "."}
            </p>
          ) : (
            <p className="small muted">At home, phones use this server's address with port 2283. To back up from anywhere, publish Immich through Remote Access.</p>
          )}
          {!st?.phoneReady && (
            <div>
              <Button onClick={() => setConfirmPublish(true)}>Phone backup from anywhere</Button>
            </div>
          )}
        </div>
      </Card>

      <Card title="Face and object search" actions={st ? <Badge tone={st.ml.lent ? "warn" : "neutral"}>{mlLabel(st.ml.mode)}</Badge> : undefined}>
        <div className="stack">
          <Field label="Runs on">
            {(id) => (
              <Select id={id} value={set.mlAcceleration} onChange={(e) => edit({ mlAcceleration: e.target.value as PhotosSettings["mlAcceleration"] })}>
                <option value="auto">A graphics card when there is one (automatic)</option>
                <option value="cpu">The processor</option>
                <option value="cuda">NVIDIA graphics card (CUDA)</option>
                <option value="openvino">Intel graphics (OpenVINO)</option>
                <option value="rocm">AMD graphics card (ROCm)</option>
              </Select>
            )}
          </Field>
          {st && <p className="small muted">{st.ml.reason}{st.ml.lent ? ". The card is with a virtual machine now: Immich uses the processor until it's back." : ""}</p>}
        </div>
      </Card>

      <Card
        title="Photos already on the server"
        actions={
          <Button
            size="sm"
            onClick={() => edit({ libraries: [...set.libraries, { ownerId: 0, share: "EXISTING", path: "", name: "" }] })}
            disabled={v.libraryShares.every((s) => !given.has(s))}
          >
            <PlusIcon size={14} /> Add a folder
          </Button>
        }
      >
        <div className="stack">
          <p className="small muted">
            Each folder appears in one person's library, read where it is: Immich doesn't move or change it. Immich can read the shared folders it was given as Existing photos (App Store › Immich › Settings).
          </p>
          {set.libraries.length === 0 && <p className="small muted">No folders yet.</p>}
          {set.libraries.map((l, i) => (
            <LibraryRow
              key={i}
              lib={l}
              users={users.data ?? []}
              shares={v.libraryShares.filter((s) => given.has(s) || s === l.share)}
              shareName={(s) => v.shares.find((x) => x.name === s)?.share || shareLabel(s)}
              state={st?.libraries.find((x) => x.name === l.name && x.importPath.endsWith(l.path))}
              onChange={(nl) => edit({ libraries: set.libraries.map((x, j) => (j === i ? nl : x)) })}
              onRemove={() => edit({ libraries: set.libraries.filter((_, j) => j !== i) })}
            />
          ))}
          <Field label="Look for new photos every (hours)">
            {(id) => (
              <TextInput id={id} type="number" min={1} max={168} value={set.scanHours} onChange={(e) => edit({ scanHours: Number(e.target.value) || 6 })} />
            )}
          </Field>
          <Toggle label="Also notice changes as they happen" description="Immich watches the folders; uses more of the server's attention with big libraries." checked={set.watch} onChange={(on) => edit({ watch: on })} />
        </div>
      </Card>

      <Card title="Family library" actions={st?.family.active ? <Badge tone="good">{st.family.members} people</Badge> : undefined}>
        <div className="stack">
          <Toggle
            label="Show the family folder to the family"
            description="Immich's own Family account owns the photos in the folder given to Immich as Family photos, and shares them with each family member (Immich › Sharing › Partners; each person can show them on their timeline)."
            checked={set.family.enabled}
            onChange={(on) => edit({ family: { ...set.family, enabled: on } })}
          />
          {set.family.enabled && !given.has("FAMILY") && <Alert tone="warn" title="Give Immich a shared folder as Family photos first (App Store › Immich › Settings)." />}
          {st?.family.problem && <Alert tone="bad" title={st.family.problem} />}
          {set.family.enabled && (
            <>
              <Field label="Name">
                {(id) => <TextInput id={id} value={set.family.name} onChange={(e) => edit({ family: { ...set.family, name: e.target.value } })} />}
              </Field>
              <MembersEditor members={set.family.members} onChange={(m) => edit({ family: { ...set.family, members: m } })} />
            </>
          )}
        </div>
      </Card>

      {st && st.people.length > 0 && (
        <Card title="People in Immich">
          <div className="stack">
            {st.people.map((p) => (
              <div key={p.immichId} className="row" style={{ justifyContent: "space-between" }}>
                <span>
                  <strong>{p.username || p.email}</strong> <span className="small muted mono">{p.email}</span>
                </span>
                <Badge tone={p.linked ? "good" : "neutral"}>{p.linked ? "Signs in with HardyOS" : "Not signed in yet"}</Badge>
              </div>
            ))}
          </div>
        </Card>
      )}

      {st && (
        <p className="small muted">
          Last applied {relativeTime(st.at)}
          {st.version ? ` to Immich ${st.version}` : ""}.{st.notes.length > 0 ? ` ${st.notes.join(". ")}.` : ""}
        </p>
      )}

      {confirmPublish && (
        <ConfirmDialog
          title="Phone backup from anywhere"
          confirmLabel="Publish Immich"
          danger={false}
          onClose={() => setConfirmPublish(false)}
          onConfirm={async () => {
            await unwrap(
              api.PUT("/apps/{id}/publish", {
                params: { path: { id: "immich" } },
                body: { mode: "public", auth: "none", groups: [], hardyosSignIn: false, confirmOpen: true },
              }),
            );
            toast("success", "Publishing Immich", "Photos applies its address once NetBird has it.");
            void qc.invalidateQueries({ queryKey: ["photos"] });
          }}
        >
          Immich goes on the internet at its own address under your base domain, with its own sign-in in front (the phone app can't get past another one). With sign-in with HardyOS on, that's your HardyOS account. Anyone can reach Immich's sign-in page.
        </ConfirmDialog>
      )}
    </>
  );
}

function LibraryRow({
  lib,
  users,
  shares,
  shareName,
  state,
  onChange,
  onRemove,
}: {
  lib: PhotosLibrary;
  users: User[];
  shares: string[];
  shareName: (s: string) => string;
  state?: { problem?: string; assets: number; immichId?: string };
  onChange: (l: PhotosLibrary) => void;
  onRemove: () => void;
}) {
  return (
    <div className="stack" style={{ padding: 10, borderRadius: 10, background: "var(--hos-surface)" }}>
      <div className="grid-2" style={{ gap: 12 }}>
        <Field label="Whose library">
          {(id) => (
            <Select id={id} value={lib.ownerId || ""} onChange={(e) => onChange({ ...lib, ownerId: Number(e.target.value) })}>
              <option value="">Choose a person</option>
              {users.map((u) => (
                <option key={u.id} value={u.id}>
                  {u.displayName ? `${u.displayName} (${u.username})` : u.username}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Field label="Library name">
          {(id) => <TextInput id={id} value={lib.name} placeholder="Old photos" onChange={(e) => onChange({ ...lib, name: e.target.value })} />}
        </Field>
        <Field label="Shared folder">
          {(id) => (
            <Select id={id} value={lib.share} onChange={(e) => onChange({ ...lib, share: e.target.value as PhotosLibrary["share"] })}>
              {shares.map((s) => (
                <option key={s} value={s}>
                  {shareName(s)}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Field label="Folder in it (empty for all of it)">
          {(id) => <TextInput id={id} value={lib.path} placeholder="Pictures/2019" onChange={(e) => onChange({ ...lib, path: e.target.value })} />}
        </Field>
      </div>
      <div className="row" style={{ justifyContent: "space-between" }}>
        <span className="small muted">{state?.problem ? <span style={{ color: "var(--hos-bad)" }}>{state.problem}</span> : state?.immichId ? `${state.assets} photos and videos` : "Not made yet"}</span>
        <IconButton label="Remove this folder" onClick={onRemove}>
          <TrashIcon size={14} />
        </IconButton>
      </div>
    </div>
  );
}

function MembersEditor({ members, onChange }: { members: AppPrincipal[]; onChange: (m: AppPrincipal[]) => void }) {
  const [kind, setKind] = useState<"user" | "group">("group");
  const [name, setName] = useState("");
  return (
    <div className="stack">
      <span className="small">
        Who sees it: {members.length === 0 ? "everyone who may use Immich" : ""}
        {members.map((m, i) => (
          <Badge key={i} tone="neutral">
            {m.kind === "group" ? "Group " : ""}
            {m.name}{" "}
            <button type="button" className="link-button" aria-label={`Remove ${m.name}`} onClick={() => onChange(members.filter((_, j) => j !== i))}>
              ×
            </button>
          </Badge>
        ))}
      </span>
      <div className="row" style={{ gap: 8 }}>
        <Select aria-label="Kind" value={kind} onChange={(e) => setKind(e.target.value as "user" | "group")}>
          <option value="group">Domain group</option>
          <option value="user">Person</option>
        </Select>
        <TextInput aria-label="Name" value={name} placeholder={kind === "group" ? "HOME\\Family" : "alice or HOME\\alice"} onChange={(e) => setName(e.target.value)} />
        <Button
          size="sm"
          disabled={!name.trim()}
          onClick={() => {
            onChange([...members, { kind, name: name.trim() }]);
            setName("");
          }}
        >
          Add
        </Button>
      </div>
    </div>
  );
}
