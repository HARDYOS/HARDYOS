import type { AuditEntry, Job } from "@hardy/api-client";
import { useInfiniteQuery } from "@tanstack/react-query";
import { useState } from "react";
import { api, unwrap } from "../api";
import { dateTime, relativeTime } from "../format";
import { useJob } from "../hooks/queries";
import { Alert, Badge, Button, EmptyState, ErrorBox, Loading, Progress, Select, type Tone } from "../ui";

const OUTCOME_TONE: Record<string, Tone> = { success: "good", failure: "bad", denied: "warn" };

const ACTION_FILTERS = [
  { value: "", label: "All activity" },
  { value: "auth.", label: "Sign-ins" },
  { value: "user.", label: "Users" },
  { value: "storage.", label: "Storage" },
  { value: "system.", label: "System" },
  { value: "recovery.", label: "Recovery" },
];

/** Audit log with filters and paging. Used by Control Panel › Security and Log Center. */
export function AuditLog() {
  const [action, setAction] = useState("");
  const q = useInfiniteQuery({
    queryKey: ["audit", action],
    initialPageParam: 0,
    queryFn: ({ pageParam }) =>
      unwrap(api.GET("/audit", { params: { query: { action: action || undefined, limit: 100, before: pageParam || undefined } } })),
    getNextPageParam: (last: AuditEntry[]) => (last.length === 100 ? last[last.length - 1]!.id : undefined),
  });
  const rows = q.data?.pages.flat() ?? [];

  return (
    <div className="stack">
      <div className="row">
        <label className="small muted" htmlFor="audit-filter">
          Show
        </label>
        <div style={{ width: 200 }}>
          <Select id="audit-filter" value={action} onChange={(e) => setAction(e.target.value)}>
            {ACTION_FILTERS.map((f) => (
              <option key={f.value} value={f.value}>
                {f.label}
              </option>
            ))}
          </Select>
        </div>
      </div>
      {q.isPending ? (
        <Loading />
      ) : q.isError ? (
        <ErrorBox error={q.error} onRetry={() => q.refetch()} />
      ) : rows.length === 0 ? (
        <EmptyState title="Nothing logged yet">Sign-ins and every change to the system show up here.</EmptyState>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>When</th>
                <th>Who</th>
                <th>Action</th>
                <th>Target</th>
                <th>Result</th>
                <th>From</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((e) => (
                <tr key={e.id}>
                  <td title={dateTime(e.at)} style={{ whiteSpace: "nowrap" }}>
                    {relativeTime(e.at)}
                  </td>
                  <td>{e.actor}</td>
                  <td className="mono small">{e.action}</td>
                  <td>
                    {e.target}
                    {e.detail && <span className="cell-sub">{e.detail}</span>}
                  </td>
                  <td>
                    <Badge tone={OUTCOME_TONE[e.outcome] ?? "neutral"}>{e.outcome}</Badge>
                  </td>
                  <td className="mono small muted">{e.ip}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {q.hasNextPage && (
        <div>
          <Button onClick={() => q.fetchNextPage()} busy={q.isFetchingNextPage}>
            Load older entries
          </Button>
        </div>
      )}
    </div>
  );
}

const STATE_TONE: Record<string, Tone> = { queued: "neutral", running: "accent", succeeded: "good", failed: "bad", cancelled: "warn" };

export function JobStateBadge({ state }: { state: Job["state"] }) {
  return <Badge tone={STATE_TONE[state] ?? "neutral"}>{state}</Badge>;
}

/** Live progress for one job, with its outcome when it finishes. */
export function JobProgress({ id, onDone }: { id: string; onDone?: (job: Job) => void }) {
  const { data: job } = useJob(id);
  const [notified, setNotified] = useState(false);
  if (!job) return <Loading label="Starting…" />;
  const done = job.state === "succeeded" || job.state === "failed" || job.state === "cancelled";
  if (done && !notified && onDone) {
    setNotified(true);
    queueMicrotask(() => onDone(job));
  }
  if (job.state === "failed") return <Alert tone="bad" title={`${job.title} failed`}>{job.error}</Alert>;
  if (job.state === "cancelled") return <Alert tone="warn" title={`${job.title} was cancelled`} />;
  if (job.state === "succeeded") return <Alert tone="good" title={`${job.title}: done`} />;
  return (
    <div className="stack" style={{ gap: 8 }}>
      <div className="row row--between small">
        <span>{job.message || (job.state === "queued" ? "Waiting to start" : "Working…")}</span>
        <span className="mono">{Math.round(job.progress)}%</span>
      </div>
      <Progress value={job.progress} label={job.title} />
    </div>
  );
}
