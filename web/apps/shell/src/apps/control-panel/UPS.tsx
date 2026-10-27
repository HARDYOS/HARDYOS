import type { UPSConfig, UPSDevice, UPSSecretsInput } from "@hardy/api-client";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, errorMessage, unwrap } from "../../api";
import { duration, relativeTime } from "../../format";
import { useUPS } from "../../hooks/monitoring";
import { useJob } from "../../hooks/queries";
import { Alert, Badge, Button, Card, ErrorBox, Field, Loading, PageHeader, Progress, Select, Stat, TextInput, Toggle } from "../../ui";
import { toast } from "../../ui/toasts";

const DRIVERS: { v: NonNullable<UPSConfig["driver"]>; label: string }[] = [
  { v: "usbhid-ups", label: "USB (most UPSes: APC, CyberPower, Eaton…)" },
  { v: "nutdrv_qx", label: "USB, Megatec/Q1 protocol (many budget UPSes)" },
  { v: "blazer_usb", label: "USB, older Megatec driver" },
  { v: "tripplite_usb", label: "Tripp Lite USB (older models)" },
  { v: "bcmxcp_usb", label: "Eaton/Powerware BCM/XCP over USB" },
  { v: "riello_usb", label: "Riello USB" },
  { v: "blazer_ser", label: "Serial, Megatec protocol" },
  { v: "apcsmart", label: "APC Smart-UPS on a serial cable" },
  { v: "dummy-ups", label: "Test: replay a file (no UPS)" },
];

export function UPS() {
  const q = useUPS();
  const qc = useQueryClient();
  const [draft, setDraft] = useState<UPSConfig | null>(null);
  const [clientPw, setClientPw] = useState("");
  const [remotePw, setRemotePw] = useState("");
  const [devices, setDevices] = useState<UPSDevice[] | null>(null);
  const [jobId, setJobId] = useState<string | null>(null);
  const job = useJob(jobId);

  const detect = useMutation({
    mutationFn: () => unwrap(api.GET("/ups/detect")),
    onSuccess: (d) => {
      setDevices(d);
      if (d.length === 0) toast("warning", "No UPS found on USB", "Check the cable, or choose the driver by hand.");
    },
  });
  const save = useMutation({
    mutationFn: (cfg: UPSConfig) => {
      const secrets: UPSSecretsInput = {};
      if (clientPw) secrets.clientPassword = clientPw;
      if (remotePw) secrets.remotePassword = remotePw;
      return unwrap(api.PUT("/ups", { body: { config: cfg, secrets } }));
    },
    onSuccess: (r) => {
      setJobId(r.job.id);
      setDraft(null);
      setClientPw("");
      setRemotePw("");
      void qc.invalidateQueries({ queryKey: ["ups"] });
    },
  });

  if (q.isPending) return <Loading />;
  if (q.isError) return <ErrorBox error={q.error} onRetry={() => q.refetch()} />;
  const v = q.data;
  const cfg: UPSConfig = draft ?? v.config;
  const edit = (p: Partial<UPSConfig>) => setDraft({ ...cfg, ...p });
  const st = v.status;
  const running = job.data && (job.data.state === "queued" || job.data.state === "running");

  return (
    <>
      <PageHeader
        title="UPS"
        subtitle="A battery backup keeps the server on through short power cuts and shuts it down cleanly before the battery runs out. HardyOS uses NUT (Network UPS Tools)."
        actions={
          <Button variant="primary" disabled={!draft} busy={save.isPending || !!running} onClick={() => save.mutate(cfg)}>
            Save and apply
          </Button>
        }
      />
      {save.error != null && <Alert tone="bad" title={errorMessage(save.error)} />}
      {job.data?.state === "failed" && <Alert tone="bad" title="Applying the UPS settings failed">{job.data.error}</Alert>}

      {cfg.mode !== "off" && v.config.mode !== "off" && (
        <Card title="Now" actions={v.checkedAt ? <span className="small muted">read {relativeTime(v.checkedAt)}</span> : undefined}>
          {!st ? (
            <Alert tone="warn" title="No reading from the UPS">
              {v.error || "Waiting for the first reading."}
            </Alert>
          ) : (
            <div className="stack">
              <div className="grid-4">
                <Stat
                  label="Power"
                  value={st.onBattery ? "On battery" : st.onLine ? "Mains" : "Unknown"}
                  tone={st.onBattery ? "warn" : st.onLine ? "good" : undefined}
                  sub={st.lowBattery ? "Battery low: shutting down" : st.charging ? "Charging" : undefined}
                />
                <Stat label="Battery" value={<span className="mono">{st.chargePct != null ? `${Math.round(st.chargePct)}%` : "–"}</span>} sub={st.lowChargePct != null ? `Shuts down at ${st.lowChargePct}%` : undefined} />
                <Stat label="Runtime" value={<span className="mono">{st.runtimeSecs != null ? duration(st.runtimeSecs) : "–"}</span>} sub={st.lowRuntimeSec != null ? `or at ${duration(st.lowRuntimeSec)} left` : undefined} />
                <Stat label="Load" value={<span className="mono">{st.loadPct != null ? `${Math.round(st.loadPct)}%` : "–"}</span>} sub={st.nominalWatts != null ? `of ${st.nominalWatts} W` : undefined} />
              </div>
              {st.chargePct != null && <Progress value={st.chargePct} tone={st.chargePct < 30 ? "bad" : st.onBattery ? "warn" : "good"} label="Battery charge" />}
              <div className="ups-flags">
                {[st.manufacturer, st.model].filter(Boolean).length > 0 && <Badge tone="neutral">{[st.manufacturer, st.model].filter(Boolean).join(" ")}</Badge>}
                {st.flags.map((f) => (
                  <Badge key={f} tone={f === "OB" || f === "LB" || f === "RB" || f === "OVER" || f === "FSD" ? "warn" : "neutral"}>
                    <span className="mono">{f}</span>
                  </Badge>
                ))}
                {st.inputVolts != null && <Badge tone="neutral">in {Math.round(st.inputVolts)} V</Badge>}
                {st.replaceBattery && <Badge tone="bad">Replace the battery</Badge>}
              </div>
            </div>
          )}
        </Card>
      )}

      <Card title="Setup">
        <div className="stack">
          <Field label="UPS">
            {(id) => (
              <Select id={id} value={cfg.mode} onChange={(e) => edit({ mode: e.target.value as UPSConfig["mode"] })}>
                <option value="off">No UPS</option>
                <option value="local">Connected to this server (USB or serial)</option>
                <option value="netclient">Connected to another server (network)</option>
              </Select>
            )}
          </Field>

          {cfg.mode === "local" && (
            <>
              <div className="row" style={{ gap: 8 }}>
                <Button onClick={() => detect.mutate()} busy={detect.isPending}>
                  Find USB UPS
                </Button>
                {devices && devices.length > 0 && <span className="small muted">Pick one to use it.</span>}
              </div>
              {devices?.map((d, i) => (
                <button
                  key={i}
                  type="button"
                  className="channel"
                  style={{ textAlign: "left", font: "inherit", color: "inherit", cursor: "pointer" }}
                  onClick={() => edit({ driver: d.driver as UPSConfig["driver"], port: d.port, vendorId: d.vendorId, productId: d.productId, serial: d.serial })}
                >
                  <strong>{[d.vendor, d.product].filter(Boolean).join(" ") || "UPS"}</strong>
                  <span className="small muted mono">
                    {d.driver} · {d.vendorId}:{d.productId}
                    {d.serial ? ` · ${d.serial}` : ""}
                  </span>
                </button>
              ))}
              <div className="grid-2" style={{ gap: 12 }}>
                <Field label="Driver">
                  {(id) => (
                    <Select id={id} value={cfg.driver ?? "usbhid-ups"} onChange={(e) => edit({ driver: e.target.value as UPSConfig["driver"], port: e.target.value === "dummy-ups" ? "ups.dev" : "auto" })}>
                      {DRIVERS.map((d) => (
                        <option key={d.v} value={d.v}>
                          {d.label}
                        </option>
                      ))}
                    </Select>
                  )}
                </Field>
                <Field label="Port" hint={cfg.driver === "dummy-ups" ? "A file in /etc/nut" : "auto for USB, /dev/ttyS0 for serial"}>
                  {(id) => <TextInput id={id} className="input mono" value={cfg.port ?? "auto"} onChange={(e) => edit({ port: e.target.value })} />}
                </Field>
                <Field label="Shut down at battery charge" hint="Percent; 0 leaves it to the UPS's own low-battery signal">
                  {(id) => <TextInput id={id} className="input mono" inputMode="numeric" value={cfg.shutdownCharge ?? 0} onChange={(e) => edit({ shutdownCharge: Number(e.target.value) || 0 })} />}
                </Field>
                <Field label="…or at runtime left" hint="Seconds; whichever comes first">
                  {(id) => <TextInput id={id} className="input mono" inputMode="numeric" value={cfg.shutdownRuntime ?? 0} onChange={(e) => edit({ shutdownRuntime: Number(e.target.value) || 0 })} />}
                </Field>
              </div>
              <Toggle
                label="Share this UPS with other servers"
                description="Other HardyOS servers on the same UPS watch it over the network (port 3493) and shut down first when the battery runs low."
                checked={!!cfg.serveNetwork}
                onChange={(on) => edit({ serveNetwork: on })}
              />
              {cfg.serveNetwork && (
                <div className="grid-2" style={{ gap: 12 }}>
                  <Field label="Listen on" hint="The address other servers reach this one on; upsd listens there and on localhost only">
                    {(id) => (
                      <Select id={id} value={cfg.listenAddress ?? ""} onChange={(e) => edit({ listenAddress: e.target.value })}>
                        <option value="">Choose an address…</option>
                        {v.addresses.map((a) => (
                          <option key={a} value={a}>
                            {a}
                          </option>
                        ))}
                      </Select>
                    )}
                  </Field>
                  <Field label="User name for other servers">
                    {(id) => <TextInput id={id} className="input mono" value={cfg.clientUser || "hardyos-client"} onChange={(e) => edit({ clientUser: e.target.value })} />}
                  </Field>
                  <Field label="Password for other servers" hint={v.secretsSet.clientPassword ? "Saved. Leave empty to keep it." : "8-64 characters, no spaces, quotes, \\ or #"}>
                    {(id) => <TextInput id={id} type="password" autoComplete="new-password" value={clientPw} placeholder={v.secretsSet.clientPassword ? "••••••••" : ""} onChange={(e) => { setClientPw(e.target.value); setDraft({ ...cfg }); }} />}
                  </Field>
                </div>
              )}
              {cfg.serveNetwork && (
                <Alert tone="info">
                  On each other server: Control Panel › UPS › Connected to another server, with this server's address, UPS name <span className="mono">{cfg.name || "ups"}</span> and the user name and password above.
                </Alert>
              )}
            </>
          )}

          {cfg.mode === "netclient" && (
            <>
              <div className="grid-2" style={{ gap: 12 }}>
                <Field label="UPS server" hint="The server the UPS is plugged into">
                  {(id) => <TextInput id={id} value={cfg.remoteHost ?? ""} placeholder="nas1.home.arpa or 192.168.1.10" onChange={(e) => edit({ remoteHost: e.target.value })} />}
                </Field>
                <div className="row" style={{ gap: 12, alignItems: "flex-start" }}>
                  <Field label="UPS name">{(id) => <TextInput id={id} className="input mono" value={cfg.remoteUps ?? "ups"} onChange={(e) => edit({ remoteUps: e.target.value })} />}</Field>
                  <Field label="Port">{(id) => <TextInput id={id} className="input mono" inputMode="numeric" value={cfg.remotePort ?? 3493} onChange={(e) => edit({ remotePort: Number(e.target.value) || 3493 })} />}</Field>
                </div>
                <Field label="User name">{(id) => <TextInput id={id} className="input mono" value={cfg.remoteUser ?? ""} placeholder="hardyos-client" onChange={(e) => edit({ remoteUser: e.target.value })} />}</Field>
                <Field label="Password" hint={v.secretsSet.remotePassword ? "Saved. Leave empty to keep it." : undefined}>
                  {(id) => <TextInput id={id} type="password" autoComplete="new-password" value={remotePw} placeholder={v.secretsSet.remotePassword ? "••••••••" : ""} onChange={(e) => { setRemotePw(e.target.value); setDraft({ ...cfg }); }} />}
                </Field>
              </div>
              <Toggle
                label="Use TLS"
                description="Encrypt the connection. The UPS server must have TLS set up in NUT."
                checked={!!cfg.remoteTls}
                onChange={(on) => edit({ remoteTls: on, remoteVerify: on ? cfg.remoteVerify : false })}
              />
              {cfg.remoteTls && (
                <Toggle
                  label="Verify its certificate"
                  description="Check the server's certificate for this host name against the system's trusted certificate authorities."
                  checked={!!cfg.remoteVerify}
                  onChange={(on) => edit({ remoteVerify: on })}
                />
              )}
              <Alert tone="warn" title="The UPS server is trusted">
                This server shuts down whenever the UPS server says so (low battery or a forced shutdown). Only connect to a server you control.
              </Alert>
            </>
          )}
        </div>
      </Card>
    </>
  );
}
