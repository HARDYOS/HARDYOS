import type { BackupRun, Job } from "@hardy/api-client";
import { useEffect, useRef } from "react";
import { useJob } from "../../hooks/queries";
import { bytes, dateTime, relativeTime } from "../../format";
import { Alert, Badge, Progress, type Tone } from "../../ui";

/** Follows a job and reports when it ends. */
export function JobProgress({ id, label, onDone }: { id: string; label: string; onDone?: (j: Job) => void }) {
  const q = useJob(id);
  const done = useRef(false);
  const j = q.data;
  useEffect(() => {
    if (j && (j.state === "succeeded" || j.state === "failed" || j.state === "cancelled") && !done.current) {
      done.current = true;
      onDone?.(j);
    }
  }, [j, onDone]);
  if (!j) return <Progress value={0} label={label} />;
  if (j.state === "failed") {
    return (
      <Alert tone="bad" title={`${label}: it didn't work`}>
        {j.error}
      </Alert>
    );
  }
  if (j.state === "cancelled") return <Alert tone="warn" title={`${label}: cancelled`} />;
  if (j.state === "succeeded") return <Alert tone="good" title={`${label}: done`} />;
  return (
    <div className="bk-job" aria-live="polite">
      <div className="bk-job__row">
        <span className="small">{j.message || label}</span>
        <span className="mono small muted">{Math.round(j.progress)}%</span>
      </div>
      <Progress value={j.progress} label={label} />
    </div>
  );
}

const stateTone: Record<string, Tone> = {
  running: "info",
  succeeded: "good",
  partial: "warn",
  failed: "bad",
  cancelled: "neutral",
  missed: "warn",
};

const stateLabel: Record<string, string> = {
  running: "Running",
  succeeded: "Done",
  partial: "Incomplete",
  failed: "Failed",
  cancelled: "Cancelled",
  missed: "Missed",
};

export function RunBadge({ run }: { run: BackupRun | null | undefined }) {
  if (!run) return <Badge tone="neutral">Never run</Badge>;
  return <Badge tone={stateTone[run.state] ?? "neutral"}>{stateLabel[run.state] ?? run.state}</Badge>;
}

/** One line about a run: when, how much. */
export function RunSummary({ run }: { run: BackupRun | null | undefined }) {
  if (!run) return <span className="muted small">No backup yet</span>;
  const when = run.finishedAt ?? run.startedAt;
  return (
    <span className="small muted" title={dateTime(when)}>
      {relativeTime(when)}
      {run.kind === "backup" && run.state !== "missed" && run.state !== "failed" && (
        <>
          {" · "}
          <span className="mono">{bytes(run.bytes)}</span> in <span className="mono">{run.files.toLocaleString()}</span> files,{" "}
          <span className="mono">{bytes(run.added)}</span> new
        </>
      )}
    </span>
  );
}

/** The gradient ring around a run's state on cards. */
export function StateDot({ state }: { state: string | undefined }) {
  return <span className={`bk-dot bk-dot--${state ?? "none"}`} aria-hidden="true" />;
}
