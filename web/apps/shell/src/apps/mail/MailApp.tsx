import type { MailManualSettings, MailMe } from "@hardy/api-client";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { api, unwrap } from "../../api";
import { bytes } from "../../format";
import { CalendarIcon, ClipboardIcon, DownloadIcon, MailIcon } from "../../icons";
import { type AppProps, useShell } from "../../shell";
import { Alert, Badge, Button, Card, EmptyState, ErrorBox, Loading, PageHeader, Progress } from "../../ui";
import { toast } from "../../ui/toasts";
import { appWindowId } from "../store/AppFrame";
import { WEBMAIL_APP_ID, deviceGuides, type DeviceKind } from "./guides";

/** The catalog app that is the desktop's webmail (Roundcube). */
export { WEBMAIL_APP_ID };

export const useMyMail = () => useQuery({ queryKey: ["mail", "me"], queryFn: () => unwrap(api.GET("/mail/me")) });

function copy(text: string) {
  void navigator.clipboard?.writeText(text).then(
    () => toast("success", "Copied"),
    () => undefined,
  );
}

function Row({ label, value, mono = true }: { label: string; value: string | number; mono?: boolean }) {
  return (
    <div className="mail-row">
      <dt className="small muted">{label}</dt>
      <dd className={mono ? "mono" : undefined}>
        {value}
        {mono && (
          <button type="button" className="mail-copy" aria-label={`Copy ${label}`} onClick={() => copy(String(value))}>
            <ClipboardIcon size={14} />
          </button>
        )}
      </dd>
    </div>
  );
}

/** Server names and ports to type into a mail app by hand. */
export function ManualSettings({ s }: { s: MailManualSettings }) {
  return (
    <dl className="mail-settings">
      <Row label="Email address" value={s.address} />
      <Row label="User name" value={s.username} />
      <Row label="Password" value="Your domain password (the one you sign in to HardyOS with)" mono={false} />
      <Row label="Incoming (IMAP) server" value={s.imapHost} />
      <Row label="IMAP port and security" value={`${s.imapPort} · ${s.imapTls}`} />
      <Row label="Outgoing (SMTP) server" value={s.smtpHost} />
      <Row label="SMTP port and security" value={`${s.smtpPort} · ${s.smtpTls} (or ${s.altSmtpPort} · STARTTLS)`} />
      <Row label="Calendars and contacts (CalDAV/CardDAV)" value={s.davUrl} />
      {s.familyCalendarUrl && <Row label="Family calendar" value={s.familyCalendarUrl} />}
      {s.familyContactsUrl && <Row label="Family address book" value={s.familyContactsUrl} />}
    </dl>
  );
}

function SetupGuide({ me }: { me: MailMe }) {
  const [kind, setKind] = useState<DeviceKind>("iphone");
  const s = me.settings;
  if (!s) return null;
  const guide = deviceGuides(s)[kind];
  return (
    <Card title="Set up my phone or computer">
      <div className="tabs" role="tablist" aria-label="Device">
        {(
          [
            ["iphone", "iPhone, iPad, Mac"],
            ["android", "Android"],
            ["thunderbird", "Thunderbird"],
            ["outlook", "Outlook"],
            ["other", "Other apps"],
          ] as const
        ).map(([id, label]) => (
          <button key={id} type="button" role="tab" className="tabs__tab" aria-selected={kind === id} onClick={() => setKind(id)}>
            {label}
          </button>
        ))}
      </div>
      <div className="stack" style={{ marginTop: 12 }}>
        <ol className="mail-steps">
          {guide.steps.map((step, i) => (
            <li key={i}>{step}</li>
          ))}
        </ol>
        {kind === "iphone" && (
          <div className="row" style={{ gap: 8 }}>
            <a className="btn btn--primary btn--md" href="/api/v1/mail/me/profile" download>
              <DownloadIcon size={16} /> Download the profile
            </a>
            <span className="small muted">Open it on the device (AirDrop or Mail it to yourself works too).</span>
          </div>
        )}
        {guide.note && <Alert tone="info">{guide.note}</Alert>}
        <details>
          <summary className="small">All the settings</summary>
          <ManualSettings s={s} />
        </details>
      </div>
    </Card>
  );
}

export default function MailApp(_: AppProps) {
  const q = useMyMail();
  const shell = useShell();
  if (q.isPending) return <Loading />;
  if (q.isError) return <ErrorBox error={q.error} onRetry={() => q.refetch()} />;
  const me = q.data;
  const m = me.mailbox;
  const openWebmail = () => shell.openApp(appWindowId(WEBMAIL_APP_ID), { id: WEBMAIL_APP_ID, title: "Mail" });

  if (!me.enabled || !m) {
    return (
      <div className="mail-app">
        <EmptyState icon={<MailIcon size={36} />} title="No mailbox here yet">
          {me.reason ?? "The mail server isn't set up."}
          {shell.user.role === "admin" && <p className="small muted">Set it up in Control Panel › Mail.</p>}
        </EmptyState>
        {shell.user.role === "admin" && (
          <div className="row" style={{ justifyContent: "center" }}>
            <Button onClick={() => shell.openApp("os.hardy.control", { section: "mail" })}>Open Control Panel › Mail</Button>
          </div>
        )}
      </div>
    );
  }
  const quota = m.quotaMb > 0 ? m.quotaMb * 1024 : 0;
  return (
    <div className="mail-app">
      <PageHeader
        title={m.address}
        subtitle={m.aliases.length > 0 ? `Also: ${m.aliases.join(", ")}` : "Your family mail, calendars and contacts, kept at home."}
        badge={m.enabled && m.accountState === "active" ? <Badge tone="good">On</Badge> : <Badge tone="bad">Off</Badge>}
        actions={
          me.webmailInstalled ? (
            <Button variant="primary" onClick={openWebmail}>
              <MailIcon size={16} /> Open webmail
            </Button>
          ) : undefined
        }
      />
      {me.reason && <Alert tone="warn" title={me.reason} />}
      {!me.webmailInstalled && (
        <Alert tone="info" title="Webmail isn't installed">
          {shell.user.role === "admin" ? "Install “Mail (Roundcube)” from the App Store to read mail in the desktop." : "Ask an administrator to install webmail from the App Store, or use a mail app."}
        </Alert>
      )}
      <Card title="Space">
        {quota > 0 ? (
          <Progress value={(me.usedKb / quota) * 100} tone={me.usedKb / quota > 0.9 ? "bad" : me.usedKb / quota > 0.75 ? "warn" : "accent"} label={`${bytes(me.usedKb * 1024)} of ${bytes(quota * 1024)}`} />
        ) : (
          <span className="mono">{bytes(me.usedKb * 1024)} used · no limit</span>
        )}
      </Card>
      <SetupGuide me={me} />
      {me.settings?.familyCalendarUrl && (
        <Card title="Family calendar and contacts">
          <div className="row" style={{ gap: 10, alignItems: "flex-start" }}>
            <CalendarIcon size={20} />
            <p className="small" style={{ margin: 0 }}>
              Everyone in the family can see and change the family calendar and address book. Your own calendars and contacts are yours alone.
              The iPhone profile adds both; elsewhere add the addresses under “All the settings”.
            </p>
          </div>
        </Card>
      )}
    </div>
  );
}
