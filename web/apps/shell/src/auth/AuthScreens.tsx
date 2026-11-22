import type { EnrollResult, LoginChallenge } from "@hardy/api-client";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useEffect, useState } from "react";
import { ApiFailure, api, errorMessage, unwrap } from "../api";
import { useCreateFirstAdmin, useLogin, useLoginCode, useSetupStatus } from "../hooks/session";
import { EnrollSteps, RecoveryCodesView } from "./TwoFactor";
import { codeReady, isChallenge, setupCodeReady } from "./twoFactorRules";
import { BrandIcon, BrandMark } from "../brand";
import { PowerIcon, RestartIcon } from "../icons";
import { Alert, Button, Field, TextInput } from "../ui";

function useClock() {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 15_000);
    return () => clearInterval(t);
  }, []);
  return now;
}

function LockClock() {
  const now = useClock();
  return (
    <div className="lock-clock">
      <span className="lock-clock__date">{now.toLocaleDateString(undefined, { weekday: "long", month: "long", day: "numeric" })}</span>
      <time className="lock-clock__time" dateTime={now.toISOString()}>
        {now.toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" }).replace(/\s?[AP]M$/i, "")}
      </time>
    </div>
  );
}

function Footer({ hostname }: { hostname?: string }) {
  return (
    <>
      <div className="lock-footer">
        <BrandMark size={20} />
        <span>HardyOS{hostname ? ` · ${hostname}` : ""}</span>
      </div>
      <div className="lock-power" aria-label="Power options (available after sign-in)">
        <span className="lock-power__btn glass" title="Restart (sign in first)">
          <RestartIcon size={18} />
        </span>
        <span className="lock-power__btn glass" title="Shut down (sign in first)">
          <PowerIcon size={18} />
        </span>
      </div>
    </>
  );
}

export function LoginScreen() {
  const login = useLogin();
  const setup = useSetupStatus();
  const domain = setup.data?.domainSignIn === true;
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [challenge, setChallenge] = useState<LoginChallenge | null>(null);

  function submit(e: FormEvent) {
    e.preventDefault();
    if (!username || !password) return;
    login.mutate(
      { username, password },
      {
        onError: () => setPassword(""),
        onSuccess: (r) => {
          setPassword("");
          if (isChallenge(r)) setChallenge(r);
        },
      },
    );
  }

  if (challenge) {
    const back = () => {
      setChallenge(null);
      login.reset();
    };
    return (
      <div className="lock-screen wallpaper">
        <LockClock />
        {challenge.step === "totp" ? <CodeStep challenge={challenge} onBack={back} /> : <EnrollStep challenge={challenge} username={username} onBack={back} />}
        <Footer />
      </div>
    );
  }

  return (
    <div className="lock-screen wallpaper">
      <LockClock />
      <form className="lock-card glass" onSubmit={submit} aria-label="Sign in">
        <div className="lock-card__brand">
          <BrandIcon size={72} />
        </div>
        <div className="lock-card__heading">
          <h1>Sign in</h1>
          <p>{domain ? "Use your HardyOS or domain account" : "Use your HardyOS account"}</p>
        </div>
        <Field label="Username" hint={domain ? "You can use your domain account: name, DOMAIN\\name or name@domain" : undefined}>
          {(id) => (
            <TextInput id={id} value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" autoCapitalize="none" spellCheck={false} required />
          )}
        </Field>
        <Field label="Password">
          {(id) => (
            <TextInput id={id} type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required />
          )}
        </Field>
        {login.error && <Alert tone="bad">{errorMessage(login.error)}</Alert>}
        <Button type="submit" variant="primary" className="btn--block btn--lg" busy={login.isPending}>
          Sign in
        </Button>
      </form>
      <Footer />
    </div>
  );
}

/** The second step: a code from the authenticator app, or a recovery code. */
function CodeStep({ challenge, onBack }: { challenge: LoginChallenge; onBack: () => void }) {
  const send = useLoginCode();
  const [code, setCode] = useState("");
  const expired = send.error instanceof ApiFailure && send.error.code === "challenge_expired";
  function submit(e: FormEvent) {
    e.preventDefault();
    if (codeReady(code)) send.mutate({ challenge: challenge.challenge, code }, { onError: () => setCode("") });
  }
  return (
    <form className="lock-card glass" onSubmit={submit} aria-label="Two-factor sign-in">
      <div className="lock-card__heading">
        <h1>Enter your code</h1>
        <p>Open your authenticator app and enter the 6-digit code for HardyOS.</p>
      </div>
      <Field label="Code" hint="Lost your phone? Enter one of your recovery codes instead.">
        {(id) => (
          <TextInput
            id={id}
            value={code}
            onChange={(e) => setCode(e.target.value)}
            inputMode="numeric"
            autoComplete="one-time-code"
            autoCapitalize="none"
            spellCheck={false}
            className="input tfa-code-input"
            autoFocus
            required
          />
        )}
      </Field>
      {send.error && <Alert tone="bad">{errorMessage(send.error)}</Alert>}
      {expired ? (
        <Button variant="primary" className="btn--block btn--lg" onClick={onBack}>
          Sign in again
        </Button>
      ) : (
        <Button type="submit" variant="primary" className="btn--block btn--lg" busy={send.isPending} disabled={!codeReady(code)}>
          Continue
        </Button>
      )}
      <Button onClick={onBack}>Back</Button>
    </form>
  );
}

/** Setting up an authenticator while signing in: an administrator past the
 *  grace period, or from outside with an administrator's setup code. */
function EnrollStep({ challenge, username, onBack }: { challenge: LoginChallenge; username: string; onBack: () => void }) {
  const qc = useQueryClient();
  const needsSetupCode = challenge.step === "setup_code";
  const [setupCode, setSetupCode] = useState("");
  const [result, setResult] = useState<EnrollResult | null>(null);
  const start = useMutation({
    mutationFn: () => unwrap(api.POST("/auth/login/enroll", { body: { challenge: challenge.challenge, setupCode: needsSetupCode ? setupCode : undefined } })),
  });
  const confirm = useMutation({
    mutationFn: (code: string) => unwrap(api.POST("/auth/login/enroll/confirm", { body: { challenge: challenge.challenge, code } })),
    onSuccess: setResult,
  });
  if (result) {
    return (
      <div className="lock-card glass lock-card--wide" aria-label="Recovery codes">
        <div className="lock-card__heading">
          <h1>Two-factor sign-in is on</h1>
        </div>
        <RecoveryCodesView codes={result.recoveryCodes} who={result.user.displayName || username} />
        <Button variant="primary" className="btn--block btn--lg" onClick={() => qc.setQueryData(["me"], result.user)}>
          I've saved them — continue
        </Button>
      </div>
    );
  }
  if (start.data) {
    return (
      <div className="lock-card glass lock-card--wide">
        <div className="lock-card__heading">
          <h1>Set up two-factor sign-in</h1>
        </div>
        <EnrollSteps enrollment={start.data} busy={confirm.isPending} error={confirm.error} onConfirm={(c) => confirm.mutate(c)} />
        <Button onClick={onBack}>Cancel</Button>
      </div>
    );
  }
  return (
    <form
      className="lock-card glass lock-card--wide"
      aria-label="Set up two-factor sign-in"
      onSubmit={(e) => {
        e.preventDefault();
        if (!needsSetupCode || setupCodeReady(setupCode)) start.mutate();
      }}
    >
      <div className="lock-card__heading">
        <h1>Set up two-factor sign-in</h1>
        <p>
          {needsSetupCode
            ? "Signing in from outside your home network needs two-factor sign-in, and your account hasn't set it up. Set it up at home, or enter the one-time setup code an administrator gave you."
            : "Administrators must use an authenticator app. Set it up now to continue."}
        </p>
      </div>
      {needsSetupCode && (
        <Field label="Setup code from your administrator">
          {(id) => <TextInput id={id} value={setupCode} onChange={(e) => setSetupCode(e.target.value)} autoComplete="off" autoCapitalize="none" spellCheck={false} className="input tfa-code-input" required />}
        </Field>
      )}
      {start.error && <Alert tone="bad">{errorMessage(start.error)}</Alert>}
      <Button type="submit" variant="primary" className="btn--block btn--lg" busy={start.isPending} disabled={needsSetupCode && !setupCodeReady(setupCode)}>
        Set up an authenticator
      </Button>
      <Button onClick={onBack}>Back</Button>
    </form>
  );
}

export function SetupScreen() {
  const create = useCreateFirstAdmin();
  const [displayName, setDisplayName] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const mismatch = confirm.length > 0 && confirm !== password;
  const tooShort = password.length > 0 && password.length < 10;

  function submit(e: FormEvent) {
    e.preventDefault();
    if (mismatch || tooShort || !username) return;
    create.mutate({ username, password, displayName });
  }

  return (
    <div className="lock-screen wallpaper">
      <div className="setup-intro">
        <BrandIcon size={72} />
        <h1>Welcome to HardyOS</h1>
        <p>Create the administrator account. It stays a local account, so you can always sign in even if other sign-in methods fail.</p>
      </div>
      <form className="lock-card glass lock-card--wide" onSubmit={submit} aria-label="Create administrator">
        <Field label="Your name" hint="Shown in the menu bar">
          {(id) => <TextInput id={id} value={displayName} onChange={(e) => setDisplayName(e.target.value)} autoComplete="name" />}
        </Field>
        <Field label="Username" hint="Lowercase letters, digits, dots, dashes">
          {(id) => (
            <TextInput
              id={id}
              value={username}
              onChange={(e) => setUsername(e.target.value.toLowerCase())}
              autoComplete="username"
              autoCapitalize="none"
              spellCheck={false}
              required
            />
          )}
        </Field>
        <Field label="Password" error={tooShort ? "At least 10 characters" : null} hint="At least 10 characters">
          {(id) => <TextInput id={id} type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" required />}
        </Field>
        <Field label="Repeat password" error={mismatch ? "Passwords don't match" : null}>
          {(id) => <TextInput id={id} type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="new-password" required />}
        </Field>
        {create.error && <Alert tone="bad">{errorMessage(create.error)}</Alert>}
        <Button type="submit" variant="primary" className="btn--block btn--lg" busy={create.isPending} disabled={mismatch || tooShort}>
          Create account and continue
        </Button>
      </form>
      <Footer />
    </div>
  );
}
