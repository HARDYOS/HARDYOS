import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { errorMessage } from "../../api";
import { useDataPools } from "../../hooks/queries";
import { dateTime } from "../../format";
import { Alert, Button, Field, Select } from "../../ui";
import { Dialog } from "../../ui/Dialog";
import { backupKeys, dismissRebuild, rebuild, useOverview, useVersions } from "./backupApi";
import { JobProgress } from "./parts";

/**
 * After a "Restore from backup" install: the settings and domain are back;
 * this offers to bring the shared folders, apps and VMs back onto a pool.
 */
export function RebuildBanner() {
  const ov = useOverview();
  const offer = ov.data?.offer ?? null;
  const [open, setOpen] = useState(false);
  const qc = useQueryClient();
  if (!offer) return null;
  const target = ov.data?.targets.find((t) => t.id === offer.target);
  return (
    <div className="bk-banner">
      <Alert
        tone="accent"
        title="Finish rebuilding this server"
        action={
          <div className="bk-banner__actions">
            <Button size="sm" variant="primary" onClick={() => setOpen(true)}>
              Rebuild…
            </Button>
            <Button
              size="sm"
              onClick={async () => {
                await dismissRebuild();
                void qc.invalidateQueries({ queryKey: backupKeys.all });
              }}
            >
              Not now
            </Button>
          </div>
        }
      >
        This server was installed from the backup at {target?.name ?? offer.target}. Its settings and accounts are back; bring back the shared folders, apps and virtual
        machines too.
      </Alert>
      {open && <RebuildDialog target={offer.target} run={offer.run} onClose={() => setOpen(false)} />}
    </div>
  );
}

export function RebuildDialog({ target, run, onClose }: { target: string; run: string; onClose: () => void }) {
  const pools = useDataPools();
  const versions = useVersions(target);
  const [pool, setPool] = useState("");
  const [job, setJob] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const v = versions.data?.versions.find((x) => x.run === run);
  const chosen = pool || pools.data?.[0]?.name || "";
  async function go() {
    setError(null);
    try {
      const r = await rebuild({ target, run, pool: chosen, confirm: "rebuild" });
      setJob(r.job.id);
    } catch (e) {
      setError(errorMessage(e));
    }
  }
  return (
    <Dialog title="Rebuild from the backup" width={520} onClose={onClose}>
      <div className="stack">
        {v && (
          <p className="small muted">
            Version from <strong>{dateTime(v.time)}</strong> with {v.items.filter((i) => i.item !== "system").length} shared folders, apps and VMs.
          </p>
        )}
        {(pools.data ?? []).length === 0 ? (
          <Alert tone="warn" title="Make a storage pool first">
            Open Storage Manager, create a pool on the data disks, then come back.
          </Alert>
        ) : (
          <Field label="Put everything on" hint="Shared folders, apps and VMs that are already here are left alone.">
            {(id) => (
              <Select id={id} value={chosen} onChange={(e) => setPool(e.target.value)}>
                {(pools.data ?? []).map((p) => (
                  <option key={p.name} value={p.name}>
                    {p.name}
                  </option>
                ))}
              </Select>
            )}
          </Field>
        )}
        {error && <Alert tone="bad">{error}</Alert>}
        {job && <JobProgress id={job} label="Rebuilding" />}
      </div>
      <footer className="dialog__foot">
        <Button onClick={onClose}>{job ? "Close" : "Cancel"}</Button>
        {!job && (
          <Button variant="primary" disabled={!chosen} onClick={go}>
            Rebuild
          </Button>
        )}
      </footer>
    </Dialog>
  );
}
