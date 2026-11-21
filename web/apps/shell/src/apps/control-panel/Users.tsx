import type { Role, User } from "@hardy/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, errorMessage, unwrap } from "../../api";
import { dateTime, initials, relativeTime } from "../../format";
import { EditIcon, KeyIcon, PlusIcon, ShieldIcon, TrashIcon } from "../../icons";
import { twoFactorLabel } from "../../auth/twoFactorRules";
import { useShell } from "../../shell";
import { Alert, Badge, Button, Card, ErrorBox, Field, IconButton, Loading, PageHeader, Select, TextInput, Toggle } from "../../ui";
import { ConfirmDialog, Dialog } from "../../ui/Dialog";
import { toast } from "../../ui/toasts";

const useUsers = () => useQuery({ queryKey: ["users"], queryFn: () => unwrap(api.GET("/users")) });

export function Users() {
  const users = useUsers();
  const { user: me } = useShell();
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<User | null>(null);
  const [resetting, setResetting] = useState<User | null>(null);
  const [deleting, setDeleting] = useState<User | null>(null);
  const [resetting2FA, setResetting2FA] = useState<User | null>(null);
  const [setupFor, setSetupFor] = useState<User | null>(null);
  const [revokeAppPw, setRevokeAppPw] = useState(true);
  const qc = useQueryClient();

  return (
    <>
      <PageHeader
        title="Users & Groups"
        subtitle="People who can sign in to HardyOS. Administrators can change system settings. Domain accounts appear here after their first sign-in."
        actions={
          <Button variant="primary" onClick={() => setCreating(true)}>
            <PlusIcon size={16} /> New user
          </Button>
        }
      />
      {users.isPending ? (
        <Loading />
      ) : users.isError ? (
        <ErrorBox error={users.error} onRetry={() => users.refetch()} />
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>User</th>
                <th>Role</th>
                <th>Status</th>
                <th>Last sign-in</th>
                <th className="actions">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {users.data.map((u) => (
                <tr key={u.id}>
                  <td>
                    <div className="row" style={{ flexWrap: "nowrap" }}>
                      <span className="avatar">{initials(u.displayName || u.username)}</span>
                      <div>
                        <strong>{u.displayName || u.username}</strong>
                        <span className="cell-sub">
                          {u.username}
                          {u.email ? ` · ${u.email}` : ""}
                        </span>
                      </div>
                    </div>
                  </td>
                  <td>
                    <div className="row">
                      <Badge tone={u.role === "admin" ? "accent" : "neutral"}>{u.role === "admin" ? "Admin" : "User"}</Badge>
                      {u.breakGlass && <Badge tone="neutral">Recovery account</Badge>}
                      {u.source === "domain" && <Badge tone="neutral">Domain</Badge>}
                    </div>
                  </td>
                  <td>
                    <div className="row">
                      {u.disabled ? <Badge tone="warn">Disabled</Badge> : <Badge tone="good">Active</Badge>}
                      <Badge tone={twoFactorLabel(u.twoFactor).tone}>{twoFactorLabel(u.twoFactor).text}</Badge>
                    </div>
                  </td>
                  <td title={dateTime(u.lastLoginAt)}>{relativeTime(u.lastLoginAt)}</td>
                  <td className="actions">
                    <IconButton label={`Edit ${u.username}`} onClick={() => setEditing(u)}>
                      <EditIcon size={16} />
                    </IconButton>
                    {u.source === "domain" ? (
                      <IconButton label={`${u.username}'s password is set in Control Panel > Domain > Users`} disabled onClick={() => undefined}>
                        <KeyIcon size={16} />
                      </IconButton>
                    ) : (
                      <IconButton label={`Set a new password for ${u.username}`} onClick={() => setResetting(u)}>
                        <KeyIcon size={16} />
                      </IconButton>
                    )}
                    {u.twoFactor?.enabled ? (
                      <IconButton label={`Reset two-factor sign-in for ${u.username}`} onClick={() => setResetting2FA(u)}>
                        <ShieldIcon size={16} />
                      </IconButton>
                    ) : (
                      <IconButton label={`One-time setup code for ${u.username} (two-factor sign-in from outside)`} onClick={() => setSetupFor(u)} disabled={u.disabled}>
                        <ShieldIcon size={16} />
                      </IconButton>
                    )}
                    <IconButton label={`Delete ${u.username}`} onClick={() => setDeleting(u)} disabled={u.id === me.id}>
                      <TrashIcon size={16} />
                    </IconButton>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {creating && <UserDialog onClose={() => setCreating(false)} />}
      {editing && <UserDialog user={editing} onClose={() => setEditing(null)} />}
      {resetting && <ResetPasswordDialog user={resetting} onClose={() => setResetting(null)} />}
      {setupFor && <SetupCodeDialog user={setupFor} onClose={() => setSetupFor(null)} />}
      {resetting2FA && (
        <ConfirmDialog
          title={`Reset two-factor sign-in for ${resetting2FA.username}?`}
          confirmLabel="Reset two-factor sign-in"
          typeToConfirm={resetting2FA.username}
          onClose={() => setResetting2FA(null)}
          onConfirm={async () => {
            await unwrap(
              api.POST("/users/{id}/2fa/reset", {
                params: { path: { id: resetting2FA.id } },
                body: { confirm: resetting2FA.username, revokeAppPasswords: revokeAppPw },
              }),
            );
            await qc.invalidateQueries({ queryKey: ["users"] });
            toast("success", `Two-factor sign-in reset for ${resetting2FA.username}`, "They were signed out everywhere.");
          }}
        >
          <p>
            Their authenticator and recovery codes stop working and they're signed out everywhere.{" "}
            {resetting2FA.role === "admin"
              ? "As an administrator they set up a new authenticator at their next sign-in, from home."
              : "They can set it up again from home, or from outside with a setup code from you."}{" "}
            Every app sign-in is revoked too. Type the username to confirm.
          </p>
          <label className="row small" style={{ gap: 6 }}>
            <input type="checkbox" checked={revokeAppPw} onChange={(e) => setRevokeAppPw(e.target.checked)} /> Also revoke their app passwords (mail,
            WebDAV, calendars)
          </label>
        </ConfirmDialog>
      )}
      {deleting && (
        <ConfirmDialog
          title={`Delete ${deleting.username}?`}
          confirmLabel="Delete user"
          onClose={() => setDeleting(null)}
          onConfirm={async () => {
            await unwrap(api.DELETE("/users/{id}", { params: { path: { id: deleting.id } } }));
            await qc.invalidateQueries({ queryKey: ["users"] });
            toast("success", `Deleted ${deleting.username}`);
          }}
        >
          {deleting.source === "domain" ? (
            <p>
              HardyOS forgets <strong>{deleting.username}</strong> and signs them out. The domain account stays, so they can sign in again; to stop that, turn the
              account off here or in Control Panel → Domain → Users.
            </p>
          ) : (
            <p>
              <strong>{deleting.displayName || deleting.username}</strong> won't be able to sign in anymore. Their files stay where they are.
            </p>
          )}
        </ConfirmDialog>
      )}
    </>
  );
}

function UserDialog({ user, onClose }: { user?: User; onClose: () => void }) {
  const qc = useQueryClient();
  const [username, setUsername] = useState(user?.username ?? "");
  const [displayName, setDisplayName] = useState(user?.displayName ?? "");
  const [email, setEmail] = useState(user?.email ?? "");
  const [role, setRole] = useState<Role>(user?.role ?? "user");
  const [disabled, setDisabled] = useState(user?.disabled ?? false);
  const [password, setPassword] = useState("");
  const fromDomain = user?.source === "domain";

  const save = useMutation({
    mutationFn: () =>
      user
        ? unwrap(
            api.PATCH("/users/{id}", {
              params: { path: { id: user.id } },
              body: fromDomain ? { disabled } : { displayName, email, role, disabled },
            }),
          )
        : unwrap(api.POST("/users", { body: { username, displayName, email, role, password } })),
    onSuccess: (u) => {
      void qc.invalidateQueries({ queryKey: ["users"] });
      toast("success", user ? `Saved ${u.username}` : `Created ${u.username}`);
      onClose();
    },
  });

  return (
    <Dialog
      title={user ? `Edit ${user.username}` : "New user"}
      onClose={onClose}
      onSubmit={() => save.mutate()}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" busy={save.isPending} disabled={!user && (!username || password.length < 10)}>
            {user ? "Save" : "Create user"}
          </Button>
        </>
      }
    >
      <div className="stack">
        {fromDomain && user && (
          <>
            <Alert tone="info" title="A domain account">
              Name, email, password and groups come from the domain: change them in Control Panel → Domain → Users. Members of Domain Admins or HardyOS
              Admins are administrators here; everyone else is a user.
            </Alert>
            {user.groups.length > 0 && (
              <p className="small muted" style={{ margin: 0 }}>
                Groups: {user.groups.map((g) => g.split("\\").pop()).join(", ")}
              </p>
            )}
            <Toggle
              label="Turned off in HardyOS"
              description="Stops this account signing in to HardyOS (and signs it out everywhere) without changing the domain."
              checked={disabled}
              onChange={setDisabled}
            />
          </>
        )}
        {!user && (
          <Field label="Username" hint="Lowercase letters, digits, dots, dashes. Can't be changed later.">
            {(id) => <TextInput id={id} value={username} onChange={(e) => setUsername(e.target.value.toLowerCase())} autoCapitalize="none" spellCheck={false} required />}
          </Field>
        )}
        {!fromDomain && (
          <>
            <Field label="Display name">{(id) => <TextInput id={id} value={displayName} onChange={(e) => setDisplayName(e.target.value)} />}</Field>
            <Field label="Email" hint="Optional; used for notifications later">
              {(id) => <TextInput id={id} type="email" value={email} onChange={(e) => setEmail(e.target.value)} />}
            </Field>
            <Field label="Role">
              {(id) => (
                <Select id={id} value={role} onChange={(e) => setRole(e.target.value as Role)}>
                  <option value="user">User: uses apps and their own files</option>
                  <option value="admin">Administrator: also manages the system</option>
                </Select>
              )}
            </Field>
          </>
        )}
        {!user && (
          <Field label="Password" hint="At least 10 characters">
            {(id) => <TextInput id={id} type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" />}
          </Field>
        )}
        {user && !fromDomain && (
          <Toggle label="Disabled" description="Disabled accounts can't sign in and are signed out everywhere." checked={disabled} onChange={setDisabled} />
        )}
        {save.error && <Alert tone="bad">{errorMessage(save.error)}</Alert>}
      </div>
    </Dialog>
  );
}

/** A one-time code that lets someone set up two-factor sign-in from outside. */
function SetupCodeDialog({ user, onClose }: { user: User; onClose: () => void }) {
  const qc = useQueryClient();
  const issue = useMutation({
    mutationFn: () => unwrap(api.POST("/users/{id}/2fa/setup-code", { params: { path: { id: user.id } } })),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["users"] }),
  });
  return (
    <Dialog
      title={`Setup code for ${user.username}`}
      description="Signing in from outside needs two-factor sign-in. Someone who can't get home to set it up can use this code once, with their password, to set it up from outside."
      onClose={onClose}
      footer={
        issue.data ? (
          <Button variant="primary" onClick={onClose}>
            Done
          </Button>
        ) : (
          <>
            <Button onClick={onClose}>Cancel</Button>
            <Button variant="primary" busy={issue.isPending} onClick={() => issue.mutate()}>
              Make a code
            </Button>
          </>
        )
      }
    >
      <div className="stack">
        {issue.data ? (
          <>
            <p className="tfa-secret tfa-secret--big">{issue.data.code}</p>
            <p className="small muted" style={{ margin: 0 }}>
              Give it to {user.displayName || user.username} in person or by phone, not by email. It works once, until {dateTime(issue.data.expiresAt)}, and
              isn't shown again.
            </p>
          </>
        ) : (
          <Alert tone="warn">Anyone with this code and the password can set up their own authenticator for this account. A new code replaces an earlier one.</Alert>
        )}
        {issue.error && <Alert tone="bad">{errorMessage(issue.error)}</Alert>}
      </div>
    </Dialog>
  );
}

/** Control Panel › Security: the administrators' grace period. */
export function TwoFactorPolicyCard() {
  const qc = useQueryClient();
  const policy = useQuery({ queryKey: ["2fa-policy"], queryFn: () => unwrap(api.GET("/auth/2fa/policy")) });
  const [days, setDays] = useState<string | null>(null);
  const save = useMutation({
    mutationFn: (n: number) => unwrap(api.PUT("/auth/2fa/policy", { body: { adminGraceDays: n } })),
    onSuccess: () => {
      setDays(null);
      void qc.invalidateQueries({ queryKey: ["2fa-policy"] });
      toast("success", "Saved");
    },
  });
  if (policy.isPending) return <Loading />;
  if (policy.isError) return <ErrorBox error={policy.error} onRetry={() => policy.refetch()} />;
  const routerSeen = policy.data.routerSeenAt;
  const value = days ?? String(policy.data.adminGraceDays);
  const n = Number(value);
  const valid = Number.isInteger(n) && n >= 0 && n <= 30;
  return (
    <Card title="Two-factor sign-in">
      <p className="small muted" style={{ margin: 0 }}>
        Everyone needs an authenticator code to sign in from outside your home network (published desktop, published apps, HardyOS sign-in); mail, WebDAV and
        calendar apps need app passwords there. Administrators must always use it. Shared folders over SMB and SFTP, and Kerberos, keep checking the domain
        password only.
      </p>
      <form
        className="row"
        onSubmit={(e) => {
          e.preventDefault();
          if (valid) save.mutate(n);
        }}
      >
        <Field label="Administrators may sign in without it for" hint="Days after the first sign-in that asks (0-30). Users and Groups shows each deadline.">
          {(id) => <TextInput id={id} type="number" min={0} max={30} value={value} onChange={(e) => setDays(e.target.value)} className="input num" style={{ width: 90 }} />}
        </Field>
        <Button type="submit" busy={save.isPending} disabled={!valid || days === null}>
          Save
        </Button>
      </form>
      {routerSeen && (
        <Alert tone="warn" title="Sign-ins through the router's own address">
          On {dateTime(routerSeen)} a request reached HardyOS from your router&apos;s address. That happens with hairpin NAT (a device at home using
          the public address) or a port forward that hides where visitors come from, and HardyOS can&apos;t tell those from someone at home: they
          don&apos;t get asked for two-factor sign-in. Don&apos;t forward ports to HardyOS (Remote Access publishes through NetBird instead), and use the
          server&apos;s local address at home.
        </Alert>
      )}
      {save.error && <Alert tone="bad">{errorMessage(save.error)}</Alert>}
    </Card>
  );
}

function ResetPasswordDialog({ user, onClose }: { user: User; onClose: () => void }) {
  const [password, setPassword] = useState("");
  const reset = useMutation({
    mutationFn: () => unwrap(api.POST("/users/{id}/password", { params: { path: { id: user.id } }, body: { password } })),
    onSuccess: () => {
      toast("success", `New password set for ${user.username}`, "They were signed out everywhere.");
      onClose();
    },
  });
  return (
    <Dialog
      title={`New password for ${user.username}`}
      description="They'll be signed out everywhere and need the new password to sign in."
      onClose={onClose}
      onSubmit={() => password.length >= 10 && reset.mutate()}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" busy={reset.isPending} disabled={password.length < 10}>
            Set password
          </Button>
        </>
      }
    >
      <div className="stack">
        <Field label="New password" hint="At least 10 characters">
          {(id) => <TextInput id={id} type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" />}
        </Field>
        {reset.error && <Alert tone="bad">{errorMessage(reset.error)}</Alert>}
      </div>
    </Dialog>
  );
}
