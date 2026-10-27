import type { NetBirdGroup, PublishItem, PublishRequest } from "@hardy/api-client";
import { useState } from "react";
import { api, errorMessage, unwrap } from "../../api";
import { ExternalIcon } from "../../icons";
import { Alert, Badge, Button, Field, Select, TextInput, Toggle } from "../../ui";
import { toast } from "../../ui/toasts";
import { publishSummary, secretProblem, serviceStatus } from "./remoteAccessRules";
import { jobDone } from "./shareServices";

type Mode = "" | "off" | "netbird" | "public";
type Auth = "sso" | "password" | "pin" | "none";

/** Sends how the desktop or an app is published (a job that also updates NetBird). */
export async function savePublish(key: string, body: PublishRequest) {
  if (key === "desktop") return jobDone(unwrap(api.PUT("/remote/desktop", { body })));
  const id = key.replace(/^app:/, "");
  return jobDone(unwrap(api.PUT("/apps/{id}/publish", { params: { path: { id } }, body })));
}

/**
 * How one thing (the desktop or an app) is published through NetBird's
 * reverse proxy: not at all, to NetBird devices only, or publicly with a
 * sign-in in front.
 */
export function PublishEditor({
  item,
  groups = [],
  supportsPrivate,
  onSaved,
}: {
  item: PublishItem;
  groups?: NetBirdGroup[];
  supportsPrivate?: boolean;
  onSaved?: () => void;
}) {
  const desktop = item.key === "desktop";
  const [mode, setMode] = useState<Mode>(item.config.default && !desktop ? "" : (item.config.mode as Mode));
  const [auth, setAuth] = useState<Auth>(item.config.auth as Auth);
  const [secret, setSecret] = useState("");
  const [signin, setSignin] = useState(item.config.hardyosSignIn);
  const [chosen, setChosen] = useState<string[]>(item.config.groups);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const effective = mode === "" ? item.config.mode : mode;
  const problem = effective === "public" ? secretProblem(auth, secret, item.config.hasSecret && item.config.auth === auth) : "";
  const st = serviceStatus(item.status);

  async function save() {
    setBusy(true);
    setError(null);
    try {
      const body: PublishRequest = { mode, auth, groups: chosen, hardyosSignIn: signin };
      if ((auth === "password" || auth === "pin") && secret !== "") body.secret = secret;
      await savePublish(item.key, body);
      setSecret("");
      toast("success", `Saved how ${item.name} is published`);
      onSaved?.();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  const toggleGroup = (id: string, on: boolean) => setChosen((g) => (on ? [...g, id] : g.filter((x) => x !== id)));

  return (
    <div className="stack">
      <div className="row" style={{ gap: 6, flexWrap: "wrap" }}>
        {item.url && (
          <a className="mono small" href={item.url} target="_blank" rel="noopener noreferrer">
            {item.url} <ExternalIcon size={12} />
          </a>
        )}
        <Badge tone="neutral">{publishSummary(item.config)}</Badge>
        {item.published && <Badge tone={st.tone}>{st.label}</Badge>}
      </div>
      {item.error && <Alert tone="warn">{item.error}</Alert>}
      <Field label="Published" hint={desktop ? "NetBird's server reaches HardyOS's sign-in through the desktop, so keep it public once HardyOS sign-in (OIDC) is set up." : undefined}>
        {(id) => (
          <Select id={id} value={mode} onChange={(e) => setMode(e.target.value as Mode)} aria-label={`How ${item.name} is published`}>
            {!desktop && <option value="">Like other apps ({item.config.default ? publishSummary(item.config) : "the default"})</option>}
            <option value="public">Public (on the internet, with sign-in in front)</option>
            <option value="netbird" disabled={supportsPrivate === false}>
              NetBird devices only{supportsPrivate === false ? " (needs a private proxy cluster)" : ""}
            </option>
            <option value="off">Not published</option>
          </Select>
        )}
      </Field>
      {effective === "public" && (
        <>
          <Field label="Sign-in in front" hint="NetBird's proxy asks for this before anything reaches HardyOS.">
            {(id) => (
              <Select id={id} value={auth} onChange={(e) => setAuth(e.target.value as Auth)}>
                <option value="sso">HardyOS sign-in (SSO)</option>
                <option value="password">A shared password</option>
                <option value="pin">A PIN</option>
                <option value="none">None{desktop ? " (the desktop's own sign-in page)" : ""}</option>
              </Select>
            )}
          </Field>
          {(auth === "password" || auth === "pin") && (
            <Field
              label={auth === "password" ? "Password" : "PIN"}
              error={secret !== "" ? problem || null : null}
              hint={item.config.hasSecret && item.config.auth === auth ? "Saved. Type a new one to change it." : undefined}
            >
              {(id) => (
                <TextInput
                  id={id}
                  type="password"
                  autoComplete="new-password"
                  inputMode={auth === "pin" ? "numeric" : undefined}
                  value={secret}
                  onChange={(e) => setSecret(e.target.value)}
                />
              )}
            </Field>
          )}
        </>
      )}
      {(effective === "netbird" || (effective === "public" && auth === "sso")) && groups.length > 0 && (
        <fieldset className="stack" style={{ border: 0, padding: 0, margin: 0, gap: 4 }}>
          <legend className="small muted">
            {effective === "netbird" ? "NetBird groups that may reach it (none chosen: All)" : "Only people in these groups (none chosen: everyone who can sign in)"}
          </legend>
          {groups.map((g) => (
            <label key={g.id} className="row small" style={{ gap: 6 }}>
              <input type="checkbox" checked={chosen.includes(g.id)} onChange={(e) => toggleGroup(g.id, e.target.checked)} />
              {g.name}
            </label>
          ))}
        </fieldset>
      )}
      {!desktop && effective !== "off" && (
        <Toggle
          label="Ask for a HardyOS sign-in too"
          description="On: the app opens only for people signed in to HardyOS who may use it (Who can use it). Off: anyone who gets past NetBird reaches the app's own sign-in, which apps with phone or TV clients need."
          checked={signin}
          onChange={setSignin}
        />
      )}
      {error && <Alert tone="bad">{error}</Alert>}
      <div className="row">
        <Button variant="primary" busy={busy} disabled={!!problem} onClick={save}>
          Save
        </Button>
      </div>
    </div>
  );
}
