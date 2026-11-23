import type { Job } from "@hardy/api-client";
import { useState } from "react";
import { Button } from "../../../ui";
import { MoveDialog } from "./MoveDialog";
import { type WorkloadKind, useClusterPlacement } from "./haApi";

/** "Move…" for a VM or app on cluster storage; nothing otherwise. */
export function MoveButton({ kind, id, name, onJob, disabled }: { kind: WorkloadKind; id: string; name: string; onJob: (j: Job) => void; disabled?: boolean }) {
  const p = useClusterPlacement(kind, id);
  const [open, setOpen] = useState(false);
  if (!p) return null;
  return (
    <>
      <Button onClick={() => setOpen(true)} disabled={disabled || !!p.target} title={`On ${p.owner || "no server"}: move it to another server`}>
        Move…
      </Button>
      {open && <MoveDialog kind={kind} id={id} name={name} onClose={() => setOpen(false)} onJob={onJob} />}
    </>
  );
}
