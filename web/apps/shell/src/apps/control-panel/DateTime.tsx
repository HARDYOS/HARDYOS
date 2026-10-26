import type { TimeConfig } from "@hardy/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import { ApiFailure, api, errorMessage, unwrap } from "../../api";
import { Alert, Badge, Button, Card, ErrorBox, Field, Loading, PageHeader, Select, TextInput, Toggle } from "../../ui";
import { toast } from "../../ui/toasts";

const useTime = () => useQuery({ queryKey: ["time"], queryFn: () => unwrap(api.GET("/system/time")), refetchInterval: 15_000 });

function zones(current: string): string[] {
  const intl = Intl as unknown as { supportedValuesOf?: (k: string) => string[] };
  const list = intl.supportedValuesOf?.("timeZone") ?? [];
  const all = new Set([...list, "Etc/UTC", current]);
  return [...all].sort();
}

/** The server's clock in its own time zone. */
function serverClock(nowISO: string, tz: string, offsetMs: number) {
  try {
    return new Intl.DateTimeFormat(undefined, { dateStyle: "full", timeStyle: "medium", timeZone: tz }).format(new Date(new Date(nowISO).getTime() + offsetMs));
  } catch {
    return new Date(nowISO).toLocaleString();
  }
}

export function DateTime() {
  const qc = useQueryClient();
  const time = useTime();
  const [draft, setDraft] = useState<TimeConfig | null>(null);
  const [servers, setServers] = useState("");
  const [manual, setManual] = useState("");
  const [tick, setTick] = useState(0);
  useEffect(() => {
    const t = setInterval(() => setTick((n) => n + 1000), 1000);
    return () => clearInterval(t);
  }, []);
  useEffect(() => setTick(0), [time.data?.now]);

  const st = time.data;
  const cfg: TimeConfig | null = draft ?? (st ? { timezone: st.timezone, ntp: st.ntp, ntpServers: st.ntpServers } : null);
  const zoneList = useMemo(() => zones(cfg?.timezone ?? "Etc/UTC"), [cfg?.timezone]);
  useEffect(() => {
    if (st && !draft) setServers(st.ntpServers.join(", "));
  }, [st, draft]);

  const save = useMutation({
    mutationFn: (c: TimeConfig) => unwrap(api.PUT("/system/time", { body: c })),
    onSuccess: (r) => {
      qc.setQueryData(["time"], r);
      setDraft(null);
      toast("success", "Date and time settings saved");
    },
  });
  const setClock = useMutation({
    mutationFn: (iso: string) => unwrap(api.POST("/system/time/clock", { body: { time: iso } })),
    onSuccess: (r) => {
      qc.setQueryData(["time"], r);
      toast("success", "Clock set");
    },
  });

  if (time.isPending) return <Loading />;
  if (time.isError) return <ErrorBox error={time.error} onRetry={() => time.refetch()} />;
  if (!st || !cfg) return null;
  const dirty = draft !== null && JSON.stringify(draft) !== JSON.stringify({ timezone: st.timezone, ntp: st.ntp, ntpServers: st.ntpServers });
  const edit = (patch: Partial<TimeConfig>) => setDraft({ ...cfg, ...patch });

  return (
    <>
      <PageHeader
        title="Date & Time"
        subtitle="The server's time zone and clock. Schedules (snapshots, scrubs) follow this time zone."
        actions={
          <Button variant="primary" disabled={!dirty} busy={save.isPending} onClick={() => save.mutate(cfg)}>
            Save
          </Button>
        }
      />
      {save.error != null && (
        <Alert tone="bad" title={errorMessage(save.error)}>
          {save.error instanceof ApiFailure && save.error.details.join("; ")}
        </Alert>
      )}
      <Card title="Server clock">
        <div className="row row--between">
          <strong style={{ fontSize: 18 }}>{serverClock(st.now, st.timezone, tick)}</strong>
          {st.ntp ? (
            st.synced ? (
              <Badge tone="good">in sync with {st.source}</Badge>
            ) : (
              <Badge tone="warn">not synced yet</Badge>
            )
          ) : (
            <Badge tone="neutral">set by hand</Badge>
          )}
        </div>
        {st.ntp && st.synced && (
          <p className="small muted" style={{ margin: 0 }}>
            Within {Math.abs(st.offsetSec) < 0.001 ? "a millisecond" : `${(Math.abs(st.offsetSec) * 1000).toFixed(1)} ms`} of the time server.
          </p>
        )}
      </Card>
      <Card title="Settings">
        <div className="stack">
          <Field label="Time zone">
            {(id) => (
              <Select id={id} value={cfg.timezone} onChange={(e) => edit({ timezone: e.target.value })} style={{ maxWidth: 320 }}>
                {zoneList.map((z) => (
                  <option key={z} value={z}>
                    {z.replaceAll("_", " ")}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          <Toggle
            label="Set the time automatically"
            description="Keeps the clock right using time servers on the internet or your network."
            checked={cfg.ntp}
            onChange={(ntp) => edit({ ntp })}
          />
          {cfg.ntp && (
            <Field label="Time servers" hint="Leave empty to use the Debian pool. Separate several with commas.">
              {(id) => (
                <TextInput
                  id={id}
                  value={servers}
                  placeholder="pool.ntp.org, 192.168.1.1"
                  onChange={(e) => {
                    setServers(e.target.value);
                    edit({ ntpServers: e.target.value.split(/[\s,]+/).filter(Boolean) });
                  }}
                  style={{ maxWidth: 420 }}
                />
              )}
            </Field>
          )}
        </div>
      </Card>
      {!st.ntp && (
        <Card title="Set the clock by hand">
          <div className="row" style={{ alignItems: "flex-end" }}>
            <Field label={`Date and time (${st.timezone.replaceAll("_", " ")})`}>
              {(id) => <TextInput id={id} type="datetime-local" step={1} value={manual} onChange={(e) => setManual(e.target.value)} />}
            </Field>
            <Button
              disabled={!manual}
              busy={setClock.isPending}
              onClick={() => {
                // The browser reads datetime-local in its own zone; the server's
                // zone may differ, so convert using the server's offset.
                setClock.mutate(zonedToUTC(manual, st.timezone));
              }}
            >
              Set clock
            </Button>
          </div>
          {setClock.error != null && <Alert tone="bad">{errorMessage(setClock.error)}</Alert>}
        </Card>
      )}
    </>
  );
}

/** Converts a wall-clock time in time zone tz to an ISO UTC string. */
export function zonedToUTC(local: string, tz: string): string {
  const asUTC = new Date(`${local.length === 16 ? `${local}:00` : local}Z`);
  // What would that UTC instant read as in tz? The difference is tz's offset.
  const parts = new Intl.DateTimeFormat("en-US", {
    timeZone: tz,
    hourCycle: "h23",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).formatToParts(asUTC);
  const get = (t: string) => Number(parts.find((p) => p.type === t)?.value);
  const seen = Date.UTC(get("year"), get("month") - 1, get("day"), get("hour"), get("minute"), get("second"));
  const offset = seen - asUTC.getTime();
  return new Date(asUTC.getTime() - offset).toISOString();
}
