import type { Share, ShareSnapshot } from "@hardy/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type KeyboardEvent, useState } from "react";
import { api, errorMessage, unwrap } from "../../api";
import { bytes, dateTime } from "../../format";
import { CameraIcon, TrashIcon } from "../../icons";
import { Alert, Badge, Button, Field, IconButton, Loading, TextInput } from "../../ui";
import { ConfirmDialog } from "../../ui/Dialog";
import { toast } from "../../ui/toasts";
import { DEFAULT_SERVICES, jobDone, saveServices } from "./shareServices";

type Kind = "hourly" | "daily" | "weekly" | "monthly";
const KINDS: { kind: Kind; label: string; max: number; hint: string }[] = [
  { kind: "hourly", label: "Hourly", max: 168, hint: "every hour" },
  { kind: "daily", label: "Daily", max: 90, hint: "at midnight UTC" },
  { kind: "weekly", label: "Weekly", max: 104, hint: "Mondays" },
  { kind: "monthly", label: "Monthly", max: 120, hint: "on the 1st" },
];

const KIND_LABEL: Record<ShareSnapshot["kind"], string> = {
  hourly: "Hourly",
  daily: "Daily",
  weekly: "Weekly",
  monthly: "Monthly",
  manual: "Taken by hand",
  other: "Other",
};

/** Same rules as the server (snapshots.CleanName). */
export function snapshotNameProblem(name: string): string | null {
  const n = name.trim();
  if (n === "") return null;
  if (n.length > 64) return "At most 64 characters.";
  if (!/^[A-Za-z0-9][A-Za-z0-9_.:-]*$/.test(n)) return "Letters a-z, digits and . _ : - only (no spaces), starting with a letter or digit.";
  if (n.toLowerCase().startsWith("hardyos-auto-")) return "Names starting with hardyos-auto- are kept for automatic snapshots.";
  return null;
}

type Counts = Record<Kind, string>;

function countsOf(share?: Share): Counts {
  const s = share?.services?.snapshots ?? DEFAULT_SERVICES.snapshots;
  return { hourly: String(s.hourly), daily: String(s.daily), weekly: String(s.weekly), monthly: String(s.monthly) };
}

/** Shared folder dialog: automatic snapshot retention, the list, take one now, delete. */
export function ShareSnapshotsSection({ share }: { share?: Share }) {
  if (!share) {
    return (
      <div className="stack" style={{ gap: 6 }}>
        <strong className="small">Snapshots</strong>
        <span className="small muted">
          Once it's made, the folder keeps 24 hourly, 14 daily, 8 weekly and 6 monthly snapshots, so older versions of its files can be brought back. Change
          that here afterwards.
        </span>
      </div>
    );
  }
  return <Snapshots share={share} />;
}

function Snapshots({ share }: { share: Share }) {
  const qc = useQueryClient();
  const key = ["shares", share.id, "snapshots"];
  const list = useQuery({
    queryKey: key,
    queryFn: () => unwrap(api.GET("/shares/{id}/snapshots", { params: { path: { id: share.id } } })).then((r) => r.snapshots),
    refetchInterval: 60_000,
  });
  const saved = countsOf(share);
  const [counts, setCounts] = useState<Counts>(saved);
  const [base, setBase] = useState<Counts>(saved);
  const [name, setName] = useState("");
  const [showAll, setShowAll] = useState(false);
  const [deleting, setDeleting] = useState<ShareSnapshot | null>(null);

  const problems = KINDS.map(({ kind, max }) => {
    const v = counts[kind].trim();
    return /^\d+$/.test(v) && Number(v) <= max ? null : `0 to ${max}`;
  });
  const changed = KINDS.some(({ kind }) => counts[kind].trim() !== base[kind]);
  const lowered = KINDS.filter(({ kind }) => Number(counts[kind]) < Number(base[kind])).map((k) => k.label.toLowerCase());

  const save = useMutation({
    mutationFn: () =>
      saveServices(share.id, (s) => ({
        ...s,
        snapshots: { hourly: Number(counts.hourly), daily: Number(counts.daily), weekly: Number(counts.weekly), monthly: Number(counts.monthly) },
      })),
    onSuccess: (sh) => {
      toast("success", "Snapshot settings saved");
      const c = countsOf(sh);
      setBase(c);
      setCounts(c);
      void qc.invalidateQueries({ queryKey: ["shares"] });
    },
  });
  const nProblem = snapshotNameProblem(name);
  const take = useMutation({
    mutationFn: () => jobDone(unwrap(api.POST("/shares/{id}/snapshots", { params: { path: { id: share.id } }, body: { name: name.trim() || undefined } }))),
    onSuccess: () => {
      toast("success", "Snapshot taken");
      setName("");
      void qc.invalidateQueries({ queryKey: key });
    },
  });

  const snaps = list.data ?? [];
  const shown = showAll ? snaps : snaps.slice(0, 8);
  const noEnter = (e: KeyboardEvent) => {
    if (e.key === "Enter") e.preventDefault();
  };

  return (
    <div className="stack" style={{ gap: 10 }}>
      <strong className="small">Snapshots</strong>
      <span className="small muted">
        Read-only copies of the folder as it was. People bring files back from them in the File Manager and in Windows' Previous Versions. Times are UTC; 0 turns
        that kind off.
      </span>
      <div className="row" style={{ gap: 8, alignItems: "flex-start" }}>
        {KINDS.map(({ kind, label, max, hint }, i) => (
          <div key={kind} style={{ flex: "1 1 100px" }}>
            <Field label={`${label} to keep`} error={problems[i]} hint={hint}>
              {(fid) => (
                <TextInput
                  id={fid}
                  className="input mono"
                  inputMode="numeric"
                  value={counts[kind]}
                  max={max}
                  onKeyDown={noEnter}
                  onChange={(e) => setCounts({ ...counts, [kind]: e.target.value })}
                />
              )}
            </Field>
          </div>
        ))}
      </div>
      {changed && lowered.length > 0 && (
        <Alert tone="warn">
          Keeping fewer {lowered.join(", ")} snapshots deletes the oldest ones beyond the new count within a minute of saving.
        </Alert>
      )}
      {changed && (
        <div className="row">
          <Button size="sm" variant="primary" disabled={problems.some(Boolean)} busy={save.isPending} onClick={() => save.mutate()}>
            Save snapshot settings
          </Button>
          <Button size="sm" onClick={() => setCounts(base)}>
            Undo
          </Button>
        </div>
      )}
      {save.isError && <Alert tone="bad">{errorMessage(save.error)}</Alert>}

      <div className="row" style={{ gap: 8, alignItems: "flex-end", flexWrap: "nowrap" }}>
        <div style={{ flex: 1 }}>
          <Field label="Take a snapshot now" error={nProblem} hint="Optional name, like before-cleanup. Snapshots you take are never deleted automatically.">
            {(fid) => (
              <TextInput
                id={fid}
                className="input mono"
                value={name}
                placeholder={`manual-${new Date().toISOString().slice(0, 10)}-…`}
                spellCheck={false}
                maxLength={64}
                onKeyDown={noEnter}
                onChange={(e) => setName(e.target.value)}
              />
            )}
          </Field>
        </div>
        <Button size="sm" disabled={!!nProblem || !share.mounted} busy={take.isPending} onClick={() => take.mutate()} style={{ marginBottom: 22 }}>
          <CameraIcon size={14} /> Take snapshot
        </Button>
      </div>
      {take.isError && <Alert tone="bad">{errorMessage(take.error)}</Alert>}

      {list.isPending ? (
        <Loading label="Loading snapshots…" />
      ) : list.isError ? (
        <Alert tone="bad">{errorMessage(list.error)}</Alert>
      ) : snaps.length === 0 ? (
        <span className="small muted">No snapshots yet. The first automatic ones are taken within a minute.</span>
      ) : (
        <div className="table-wrap">
          <table className="table" aria-label={`Snapshots of ${share.name}`}>
            <thead>
              <tr>
                <th>Snapshot</th>
                <th>Taken</th>
                <th>Only in it</th>
                <th className="actions">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {shown.map((s) => (
                <tr key={s.name}>
                  <td>
                    <span className="mono small">{s.name}</span>
                    <div>
                      <Badge tone={s.kind === "manual" ? "accent" : s.kind === "other" ? "neutral" : "info"}>{KIND_LABEL[s.kind]}</Badge>
                    </div>
                  </td>
                  <td className="small">{dateTime(s.createdAt)}</td>
                  <td className="mono small">{bytes(s.usedBytes)}</td>
                  <td className="actions">
                    <IconButton label={`Delete snapshot ${s.name}`} onClick={() => setDeleting(s)}>
                      <TrashIcon size={16} />
                    </IconButton>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {snaps.length > shown.length && (
        <div>
          <Button size="sm" variant="ghost" onClick={() => setShowAll(true)}>
            Show all {snaps.length}
          </Button>
        </div>
      )}
      {deleting && (
        <ConfirmDialog
          title="Delete this snapshot?"
          confirmLabel="Delete snapshot"
          onClose={() => setDeleting(null)}
          onConfirm={async () => {
            await jobDone(
              unwrap(
                api.DELETE("/shares/{id}/snapshots/{snapshot}", {
                  params: { path: { id: share.id, snapshot: deleting.name } },
                  body: { confirm: deleting.name },
                }),
              ),
            );
            toast("success", "Snapshot deleted");
            void qc.invalidateQueries({ queryKey: key });
          }}
        >
          <span className="mono">{deleting.name}</span> ({dateTime(deleting.createdAt)}) is deleted for good, and the {bytes(deleting.usedBytes)} only it holds is
          freed. The files in {share.name} now aren't touched.
        </ConfirmDialog>
      )}
    </div>
  );
}
