import type { MonitorSettings } from "@hardy/api-client";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, errorMessage, unwrap } from "../../api";
import { useMonitorSettings } from "../../hooks/monitoring";
import { Alert, Button, Card, ErrorBox, Field, Loading, PageHeader, Select, TextInput, Toggle } from "../../ui";
import { toast } from "../../ui/toasts";
import { ConditionList } from "../monitor/parts";

const hours = Array.from({ length: 24 }, (_, h) => h);
const hourLabel = (h: number) => `${String(h).padStart(2, "0")}:00`;

/** Pool and disk health: what's wrong now, the self-test and scrub
 * schedule, and the alert thresholds. */
export function Health() {
  return (
    <>
      <PageHeader title="Health" subtitle="Pools and disks: problems right now, when disks test themselves and when you're warned." />
      <Card title="Needs attention">
        <ConditionList prefixes={["pool.", "disk."]} emptyText="Every pool is healthy and every disk reports good SMART health." />
      </Card>
      <ScheduleCard />
    </>
  );
}

function num(v: string, fallback: number) {
  const n = Number(v);
  return Number.isFinite(n) && v.trim() !== "" ? Math.round(n) : fallback;
}

function ScheduleCard() {
  const q = useMonitorSettings();
  const qc = useQueryClient();
  const [draft, setDraft] = useState<MonitorSettings | null>(null);
  const save = useMutation({
    mutationFn: (s: MonitorSettings) => unwrap(api.PUT("/monitor/settings", { body: s })),
    onSuccess: (r) => {
      qc.setQueryData(["monitor-settings"], r);
      void qc.invalidateQueries({ queryKey: ["disk-info"] });
      setDraft(null);
      toast("success", "Health settings saved");
    },
  });
  if (q.isPending) return <Loading />;
  if (q.isError) return <ErrorBox error={q.error} onRetry={() => q.refetch()} />;
  const s = draft ?? q.data;
  const edit = (p: Partial<MonitorSettings>) => setDraft({ ...s, ...p });
  const sched = (p: Partial<MonitorSettings["smart"]>) => edit({ smart: { ...s.smart, ...p } });
  const numField = (label: string, value: number, onChange: (n: number) => void, hint?: string) => (
    <Field label={label} hint={hint}>
      {(id) => <TextInput id={id} className="input mono" inputMode="numeric" style={{ maxWidth: 110 }} value={value} onChange={(e) => onChange(num(e.target.value, value))} />}
    </Field>
  );

  return (
    <Card
      title="Schedule and thresholds"
      actions={
        <Button size="sm" variant="primary" disabled={!draft} busy={save.isPending} onClick={() => save.mutate(s)}>
          Save
        </Button>
      }
    >
      <div className="stack">
        <Toggle
          label="Disk self-tests"
          description="Each disk tests itself on a schedule. Disks take turns: one long test at a time, never while its pool scrubs."
          checked={s.smart.enabled}
          onChange={(v) => sched({ enabled: v })}
        />
        <div className="row" style={{ gap: 12, flexWrap: "wrap", alignItems: "flex-start" }}>
          {numField("Short test every", s.smart.shortDays, (n) => sched({ shortDays: n }), "days (a few minutes)")}
          {numField("Long test every", s.smart.longDays, (n) => sched({ longDays: n }), "days (hours on big disks)")}
          <Field label="Between" hint="Server time">
            {(id) => (
              <Select id={id} value={s.smart.windowStart} onChange={(e) => sched({ windowStart: Number(e.target.value) })}>
                {hours.map((h) => (
                  <option key={h} value={h}>
                    {hourLabel(h)}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          <Field label="And">
            {(id) => (
              <Select id={id} value={s.smart.windowEnd} onChange={(e) => sched({ windowEnd: Number(e.target.value) })}>
                {hours.map((h) => (
                  <option key={h} value={h}>
                    {hourLabel(h)}
                  </option>
                ))}
              </Select>
            )}
          </Field>
        </div>
        <Toggle
          label="Scrub pools in the same hours"
          description="Scheduled scrubs (Schedules) wait for this window and run one pool at a time."
          checked={s.smart.scrubInWindow}
          onChange={(v) => sched({ scrubInWindow: v })}
        />
        <div className="row" style={{ gap: 12, flexWrap: "wrap", alignItems: "flex-start" }}>
          {numField("Pool warning at", s.poolWarnPct, (n) => edit({ poolWarnPct: n }), "% full")}
          {numField("Pool critical at", s.poolCritPct, (n) => edit({ poolCritPct: n }), "% full")}
          {numField("Hard disk warm", s.hddWarnC, (n) => edit({ hddWarnC: n }), "°C")}
          {numField("Hard disk hot", s.hddCritC, (n) => edit({ hddCritC: n }), "°C")}
          {numField("SSD warm", s.ssdWarnC, (n) => edit({ ssdWarnC: n }), "°C")}
          {numField("SSD hot", s.ssdCritC, (n) => edit({ ssdCritC: n }), "°C")}
        </div>
        {save.error != null && <Alert tone="bad">{errorMessage(save.error)}</Alert>}
      </div>
    </Card>
  );
}
