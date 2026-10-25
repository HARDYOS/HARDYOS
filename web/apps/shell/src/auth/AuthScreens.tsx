import { type FormEvent, useEffect, useState } from "react";
import { errorMessage } from "../api";
import { useCreateFirstAdmin, useLogin } from "../hooks/session";
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
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  function submit(e: FormEvent) {
    e.preventDefault();
    if (!username || !password) return;
    login.mutate({ username, password }, { onError: () => setPassword("") });
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
          <p>Use your HardyOS account</p>
        </div>
        <Field label="Username">
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
