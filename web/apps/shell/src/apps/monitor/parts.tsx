import type { Condition } from "@hardy/api-client";
import { dateTime, relativeTime } from "../../format";
import { useConditions } from "../../hooks/monitoring";
import { AlertIcon, CheckIcon, InfoIcon } from "../../icons";
import { openLink } from "../../links";
import { useShell } from "../../shell";
import { Button, EmptyState, ErrorBox, Loading } from "../../ui";
import type { HistoryRange } from "../../hooks/monitoring";
import { RANGES } from "../../hooks/monitoring";

const SEV_LABEL: Record<string, string> = { critical: "Critical", warning: "Warning", info: "Notice" };

/** What's wrong right now, most severe first; filter by key prefix. */
export function ConditionList({
  prefixes,
  match,
  emptyText = "Nothing needs attention.",
  hideEmpty,
}: {
  prefixes?: string[];
  match?: (key: string) => boolean;
  emptyText?: string;
  hideEmpty?: boolean;
}) {
  const q = useConditions();
  const { user } = useShell();
  if (q.isPending) return hideEmpty ? null : <Loading />;
  if (q.isError) return hideEmpty ? null : <ErrorBox error={q.error} onRetry={() => q.refetch()} />;
  const list = q.data.filter((c) => (!prefixes || prefixes.some((p) => c.key.startsWith(p))) && (!match || match(c.key)));
  if (list.length === 0 && hideEmpty) return null;
  if (list.length === 0) return <EmptyState icon={<CheckIcon size={22} />} title="All clear">{emptyText}</EmptyState>;
  return (
    <ul className="cond-list">
      {list.map((c) => (
        <ConditionRow key={c.key} c={c} onOpen={c.link ? () => openLink(c.link, user) : undefined} />
      ))}
    </ul>
  );
}

function ConditionRow({ c, onOpen }: { c: Condition; onOpen?: () => void }) {
  return (
    <li className="cond">
      <span className={`cond__icon cond__icon--${c.severity}`} aria-hidden="true">
        {c.severity === "info" ? <InfoIcon size={18} /> : <AlertIcon size={18} />}
      </span>
      <div className="cond__text">
        <strong>
          <span className="sr-only">{SEV_LABEL[c.severity]}: </span>
          {c.title}
        </strong>
        {c.body && <p>{c.body}</p>}
        <time dateTime={c.since} title={dateTime(c.since)}>
          {SEV_LABEL[c.severity]} · since {relativeTime(c.since)}
        </time>
      </div>
      {onOpen && (
        <Button size="sm" onClick={onOpen} className="cond__open">
          Open
        </Button>
      )}
    </li>
  );
}

/** The range picker: presets in one row. */
export function RangePicker({ value, onChange }: { value: HistoryRange; onChange: (r: HistoryRange) => void }) {
  return (
    <div className="seg" role="group" aria-label="Time range">
      {RANGES.map((r) => (
        <button key={r} type="button" aria-pressed={value === r} onClick={() => onChange(r)}>
          {r}
        </button>
      ))}
    </div>
  );
}
