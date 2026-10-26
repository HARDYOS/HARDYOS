import type { Role, User } from "@hardy/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, errorMessage, unwrap } from "../../api";
import { dateTime, initials, relativeTime } from "../../format";
import { EditIcon, KeyIcon, PlusIcon, TrashIcon } from "../../icons";
import { useShell } from "../../shell";
import { Alert, Badge, Button, ErrorBox, Field, IconButton, Loading, PageHeader, Select, TextInput, Toggle } from "../../ui";
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
                  <td>{u.disabled ? <Badge tone="warn">Disabled</Badge> : <Badge tone="good">Active</Badge>}</td>
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
