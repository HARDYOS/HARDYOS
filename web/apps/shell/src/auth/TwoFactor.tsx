import type { AppPassword, AppPasswordScope, Enrollment, QRCode, User } from "@hardy/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { api, errorMessage, unwrap } from "../api";
import { dateTime, relativeTime } from "../format";
import { KeyIcon, PlusIcon, ShieldIcon, TrashIcon } from "../icons";
import { Alert, Badge, Button, Field, IconButton, Loading, TextInput } from "../ui";
import { ConfirmDialog, Dialog } from "../ui/Dialog";
import { toast } from "../ui/toasts";
import { SCOPE_LABELS, codeReady, recoveryCodesText, totpReady } from "./twoFactorRules";

/** The enrollment QR code, drawn from the server's path data (no image requests). */
export function QRCodeView({ qr, size = 200 }: { qr: QRCode; size?: number }) {
  return (
    <svg
      className="tfa-qr"
      role="img"
      aria-label="QR code to scan with your authenticator app"
      viewBox={`0 0 ${qr.size} ${qr.size}`}
      width={size}
      height={size}
      shapeRendering="crispEdges"
    >
      <rect width={qr.size} height={qr.size} fill="#fff" />
      <path d={qr.path} fill="#000" />
    </svg>
  );
}

/** Recovery codes, shown once, with copy and save. */
export function RecoveryCodesView({ codes, who }: { codes: string[]; who: string }) {
  const text = recoveryCodesText(codes, who, window.location.hostname);
  const href = `data:text/plain;charset=utf-8,${encodeURIComponent(text)}`;
  return (
    <div className="stack">
      <Alert tone="warn" title="Save these now">
        Each code signs you in once if you lose your phone. They aren't shown again.
      </Alert>
      <ol className="tfa-codes" aria-label="Recovery codes">
        {codes.map((c) => (
          <li key={c}>{c}</li>
        ))}
      </ol>
      <div className="row">
        <Button
          onClick={() => {
            void navigator.clipboard?.writeText(text).then(() => toast("success", "Recovery codes copied"));
          }}
        >
          Copy
        </Button>
        <a className="btn btn--secondary btn--md" href={href} download="hardyos-recovery-codes.txt">
          Download
        </a>
      </div>
    </div>
  );
}

/** Scan (or type) the secret, then the first code. */
export function EnrollSteps({
  enrollment,
  busy,
  error,
  onConfirm,
  submitLabel = "Turn on two-factor sign-in",
}: {
  enrollment: Enrollment;
  busy: boolean;
  error: unknown;
  onConfirm: (code: string) => void;
  submitLabel?: string;
}) {
  const [code, setCode] = useState("");
  function submit(e: FormEvent) {
    e.preventDefault();
    if (totpReady(code)) onConfirm(code);
  }
  return (
    <form className="stack" onSubmit={submit} aria-label="Set up an authenticator">
      <ol className="tfa-steps small">
        <li>Open an authenticator app (Google Authenticator, Microsoft Authenticator, 1Password, Bitwarden, Aegis…).</li>
        <li>Scan this code, or add the key below by hand (time-based, 6 digits).</li>
        <li>Enter the 6-digit code the app shows.</li>
      </ol>
      <div className="tfa-qr-box">
        <QRCodeView qr={enrollment.qr} />
      </div>
      <p className="tfa-secret" aria-label="Key to type into the app">
        {enrollment.secret}
      </p>
      <Field label="Code from the app">
        {(id) => (
          <TextInput
            id={id}
            value={code}
            onChange={(e) => setCode(e.target.value)}
            inputMode="numeric"
            autoComplete="one-time-code"
            className="input tfa-code-input"
            maxLength={8}
            required
          />
        )}
      </Field>
      {error ? <Alert tone="bad">{errorMessage(error)}</Alert> : null}
      <Button type="submit" variant="primary" className="btn--block" busy={busy} disabled={!totpReady(code)}>
        {submitLabel}
      </Button>
    </form>
  );
}

type Action = "enroll" | "replace" | "recovery" | "disable";

const ACTION_TITLES: Record<Action, string> = {
  enroll: "Set up two-factor sign-in",
  replace: "Set up a new authenticator",
  recovery: "New recovery codes",
  disable: "Turn off two-factor sign-in",
};

/** Your account's two-factor sign-in and app passwords (account menu). */
export function TwoFactorDialog({ user, onClose }: { user: User; onClose: () => void }) {
  const qc = useQueryClient();
  const status = useQuery({ queryKey: ["2fa"], queryFn: () => unwrap(api.GET("/auth/2fa")) });
  const [action, setAction] = useState<Action | null>(null);
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [enrollment, setEnrollment] = useState<Enrollment | null>(null);
  const [codes, setCodes] = useState<string[] | null>(null);
  const who = user.displayName || user.username;

  const refresh = () => {
    void qc.invalidateQueries({ queryKey: ["2fa"] });
    void qc.invalidateQueries({ queryKey: ["me"] });
  };
  const start = useMutation({
    mutationFn: async () => {
      const body = { password, code: code || undefined };
      switch (action) {
        case "recovery":
          return { codes: (await unwrap(api.POST("/auth/2fa/recovery-codes", { body }))).recoveryCodes };
        case "disable":
          await unwrap(api.POST("/auth/2fa/disable", { body: { password, code } }));
          return { disabled: true };
        default:
          return { enrollment: await unwrap(api.POST("/auth/2fa/enroll", { body })) };
      }
    },
    onSuccess: (r) => {
      setPassword("");
      setCode("");
      if ("enrollment" in r && r.enrollment) setEnrollment(r.enrollment);
      if ("codes" in r && r.codes) {
        setCodes(r.codes);
        refresh();
      }
      if ("disabled" in r) {
        toast("success", "Two-factor sign-in is off");
        setAction(null);
        refresh();
      }
    },
  });
  const confirm = useMutation({
    mutationFn: (c: string) => unwrap(api.POST("/auth/2fa/confirm", { body: { code: c } })),
    onSuccess: (r) => {
      setEnrollment(null);
      setCodes(r.recoveryCodes);
      refresh();
      toast("success", "Two-factor sign-in is on", "Your other devices were signed out.");
    },
  });

  const dismiss = useMutation({
    mutationFn: () => unwrap(api.POST("/auth/2fa/notice/dismiss")),
    onSuccess: refresh,
  });
  const st = status.data;
  const reset = () => {
    setAction(null);
    setEnrollment(null);
    setCodes(null);
    start.reset();
    confirm.reset();
  };

  let body;
  if (status.isPending) body = <Loading />;
  else if (status.isError) body = <Alert tone="bad">{errorMessage(status.error)}</Alert>;
  else if (codes) body = <RecoveryCodesView codes={codes} who={who} />;
  else if (enrollment) body = <EnrollSteps enrollment={enrollment} busy={confirm.isPending} error={confirm.error} onConfirm={(c) => confirm.mutate(c)} />;
  else if (action) {
    const needsCode = action !== "enroll";
    body = (
      <form
        className="stack"
        onSubmit={(e) => {
          e.preventDefault();
          if (password && (!needsCode || codeReady(code))) start.mutate();
        }}
      >
        <p className="small muted" style={{ margin: 0 }}>
          {action === "disable"
            ? "Signing in from outside your home network won't work any more until you set it up again."
            : "Enter your password to go on."}
        </p>
        <Field label="Password">
          {(id) => <TextInput id={id} type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required />}
        </Field>
        {needsCode && (
          <Field label="Code from your authenticator app" hint="Or one of your recovery codes">
            {(id) => <TextInput id={id} value={code} onChange={(e) => setCode(e.target.value)} autoComplete="one-time-code" className="input tfa-code-input" required />}
          </Field>
        )}
        {start.error && <Alert tone="bad">{errorMessage(start.error)}</Alert>}
        <div className="row" style={{ justifyContent: "flex-end" }}>
          <Button onClick={reset}>Back</Button>
          <Button type="submit" variant={action === "disable" ? "danger" : "primary"} busy={start.isPending} disabled={!password || (needsCode && !codeReady(code))}>
            {action === "disable" ? "Turn off" : "Continue"}
          </Button>
        </div>
      </form>
    );
  } else if (st) {
    body = (
      <div className="stack">
        <div className="row tfa-status">
          <ShieldIcon size={20} />
          {st.enabled ? <Badge tone="good">On</Badge> : <Badge tone={st.required ? "warn" : "neutral"}>Off</Badge>}
          {st.locked && <Badge tone="bad">Codes from outside off</Badge>}
        </div>
        {st.notice && (
          <Alert tone="warn" title="Wrong codes for your account" action={<Button size="sm" onClick={() => dismiss.mutate()}>Dismiss</Button>}>
            {st.notice}
          </Alert>
        )}
        {st.locked && (
          <p className="small muted" style={{ margin: 0 }}>
            Too many wrong codes from outside: authenticator codes work only at home until you change your password (or an administrator resets
            two-factor sign-in). Recovery codes work everywhere.
          </p>
        )}
        {st.enabled ? (
          <p className="small muted" style={{ margin: 0 }}>
            Turned on {relativeTime(st.enabledAt)} · <span className="num">{st.recoveryCodesLeft}</span> recovery codes left
            {st.outsideFailures > 0 && (
              <>
                {" "}
                · <span className="num">{st.outsideFailures}</span> wrong codes from outside in 60 days
              </>
            )}
          </p>
        ) : (
          <p className="small muted" style={{ margin: 0 }}>
            After your password, HardyOS asks for a code from an app on your phone. It's needed whenever you sign in from outside your home network
            {st.required ? ", and administrators must always use it" : ""}.
            {st.graceUntil ? ` Set it up by ${dateTime(st.graceUntil)}.` : ""}
          </p>
        )}
        <div className="row">
          {st.enabled ? (
            <>
              <Button onClick={() => setAction("recovery")}>New recovery codes</Button>
              <Button onClick={() => setAction("replace")}>New phone</Button>
              {!st.required && (
                <Button variant="danger" onClick={() => setAction("disable")}>
                  Turn off
                </Button>
              )}
            </>
          ) : (
            <Button variant="primary" onClick={() => setAction("enroll")}>
              Set up two-factor sign-in
            </Button>
          )}
        </div>
        {user.source === "domain" && <AppPasswords enrolled={st.enabled} />}
      </div>
    );
  }

  return (
    <Dialog title={action ? ACTION_TITLES[action] : "Two-factor sign-in"} onClose={onClose} width={520}
      footer={codes ? <Button variant="primary" onClick={reset}>I've saved them</Button> : <Button onClick={onClose}>Close</Button>}
    >
      {body}
    </Dialog>
  );
}

/** Per-device passwords for WebDAV, mail and calendars. */
function AppPasswords({ enrolled }: { enrolled: boolean }) {
  const qc = useQueryClient();
  const list = useQuery({ queryKey: ["app-passwords"], queryFn: () => unwrap(api.GET("/auth/app-passwords")) });
  const [creating, setCreating] = useState(false);
  const [revoking, setRevoking] = useState<AppPassword | null>(null);
  return (
    <section className="stack tfa-apps" aria-label="App passwords">
      <div className="row" style={{ justifyContent: "space-between" }}>
        <strong>App passwords</strong>
        <Button size="sm" onClick={() => setCreating(true)}>
          <PlusIcon size={14} /> New
        </Button>
      </div>
      <p className="small muted" style={{ margin: 0 }}>
        For mail apps, mapped drives (WebDAV) and calendar apps, which can't ask for a code. From outside your home network only app passwords work there
        {enrolled ? ", and with two-factor sign-in on, your own password no longer works there at all" : ""}. Shared folders over SMB and SFTP keep using your
        domain password.
      </p>
      {list.isPending ? (
        <Loading />
      ) : list.isError ? (
        <Alert tone="bad">{errorMessage(list.error)}</Alert>
      ) : list.data.length === 0 ? (
        <p className="small muted" style={{ margin: 0 }}>
          None yet.
        </p>
      ) : (
        <ul className="tfa-applist">
          {list.data.map((p) => (
            <li key={p.id}>
              <KeyIcon size={16} />
              <div>
                <strong>{p.name}</strong>
                <span className="cell-sub">
                  {p.scopes.map((s) => SCOPE_LABELS[s]).join(" · ")} · {p.lastUsedAt ? `used ${relativeTime(p.lastUsedAt)}` : "never used"}
                </span>
              </div>
              <IconButton label={`Revoke ${p.name}`} onClick={() => setRevoking(p)}>
                <TrashIcon size={16} />
              </IconButton>
            </li>
          ))}
        </ul>
      )}
      {creating && <NewAppPasswordDialog onClose={() => setCreating(false)} />}
      {revoking && (
        <ConfirmDialog
          title={`Revoke ${revoking.name}?`}
          confirmLabel="Revoke"
          onClose={() => setRevoking(null)}
          onConfirm={async () => {
            await unwrap(api.DELETE("/auth/app-passwords/{id}", { params: { path: { id: revoking.id } } }));
            await qc.invalidateQueries({ queryKey: ["app-passwords"] });
            toast("success", `Revoked ${revoking.name}`);
          }}
        >
          <p>Apps using it stop signing in at once.</p>
        </ConfirmDialog>
      )}
    </section>
  );
}

function NewAppPasswordDialog({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [scopes, setScopes] = useState<AppPasswordScope[]>(["mail"]);
  const [password, setPassword] = useState("");
  const create = useMutation({
    mutationFn: () => unwrap(api.POST("/auth/app-passwords", { body: { name, scopes, password } })),
    onSuccess: () => {
      setPassword("");
      void qc.invalidateQueries({ queryKey: ["app-passwords"] });
    },
  });
  const toggle = (s: AppPasswordScope) => setScopes((cur) => (cur.includes(s) ? cur.filter((x) => x !== s) : [...cur, s]));
  if (create.data) {
    return (
      <Dialog title="Your new app password" onClose={onClose} footer={<Button variant="primary" onClick={onClose}>Done</Button>}>
        <div className="stack">
          <p className="small muted" style={{ margin: 0 }}>
            Type it into <strong>{create.data.appPassword.name}</strong> instead of your password. It isn't shown again.
          </p>
          <p className="tfa-secret tfa-secret--big">{create.data.password}</p>
        </div>
      </Dialog>
    );
  }
  return (
    <Dialog
      title="New app password"
      onClose={onClose}
      onSubmit={() => name && scopes.length > 0 && password && create.mutate()}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" busy={create.isPending} disabled={!name || scopes.length === 0 || !password}>
            Create
          </Button>
        </>
      }
    >
      <div className="stack">
        <Field label="Device or app" hint="So you know which one to revoke, e.g. “Phone mail”">
          {(id) => <TextInput id={id} value={name} onChange={(e) => setName(e.target.value)} maxLength={64} required />}
        </Field>
        <fieldset className="tfa-scopes">
          <legend className="small">Can sign in to</legend>
          {(Object.keys(SCOPE_LABELS) as AppPasswordScope[]).map((s) => (
            <label key={s} className="row small">
              <input type="checkbox" checked={scopes.includes(s)} onChange={() => toggle(s)} /> {SCOPE_LABELS[s]}
            </label>
          ))}
        </fieldset>
        <Field label="Your password">
          {(id) => <TextInput id={id} type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required />}
        </Field>
        {create.error && <Alert tone="bad">{errorMessage(create.error)}</Alert>}
      </div>
    </Dialog>
  );
}

/** Shown instead of the desktop to an administrator past the grace period. */
export function EnrollRequired({ user, onSignOut }: { user: User; onSignOut: () => void }) {
  const qc = useQueryClient();
  const [password, setPassword] = useState("");
  const [enrollment, setEnrollment] = useState<Enrollment | null>(null);
  const [codes, setCodes] = useState<string[] | null>(null);
  const start = useMutation({
    mutationFn: () => unwrap(api.POST("/auth/2fa/enroll", { body: { password } })),
    onSuccess: (e) => {
      setPassword("");
      setEnrollment(e);
    },
  });
  const confirm = useMutation({
    mutationFn: (c: string) => unwrap(api.POST("/auth/2fa/confirm", { body: { code: c } })),
    onSuccess: (r) => {
      setEnrollment(null);
      setCodes(r.recoveryCodes);
    },
  });
  return (
    <div className="lock-screen wallpaper">
      <div className="lock-card glass lock-card--wide" aria-label="Set up two-factor sign-in">
        <div className="lock-card__heading">
          <h1>Set up two-factor sign-in</h1>
          <p>Administrators must use an authenticator app. Set it up now to continue to the desktop.</p>
        </div>
        {codes ? (
          <>
            <RecoveryCodesView codes={codes} who={user.displayName || user.username} />
            <Button variant="primary" className="btn--block btn--lg" onClick={() => void qc.invalidateQueries({ queryKey: ["me"] })}>
              I've saved them — continue
            </Button>
          </>
        ) : enrollment ? (
          <EnrollSteps enrollment={enrollment} busy={confirm.isPending} error={confirm.error} onConfirm={(c) => confirm.mutate(c)} />
        ) : (
          <form
            className="stack"
            onSubmit={(e) => {
              e.preventDefault();
              if (password) start.mutate();
            }}
          >
            <Field label="Your password">
              {(id) => <TextInput id={id} type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required />}
            </Field>
            {start.error && <Alert tone="bad">{errorMessage(start.error)}</Alert>}
            <Button type="submit" variant="primary" className="btn--block btn--lg" busy={start.isPending} disabled={!password}>
              Continue
            </Button>
          </form>
        )}
        <Button onClick={onSignOut}>Sign out</Button>
      </div>
    </div>
  );
}
