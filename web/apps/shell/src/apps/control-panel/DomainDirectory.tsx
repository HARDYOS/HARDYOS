import type { DomainGroup, DomainUser } from "@hardy/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, errorMessage, unwrap } from "../../api";
import { initials, relativeTime } from "../../format";
import { EditIcon, KeyIcon, PlusIcon, TrashIcon, UsersIcon } from "../../icons";
import { Alert, Badge, Button, Card, EmptyState, ErrorBox, Field, IconButton, Loading, TextInput, Toggle } from "../../ui";
import { ConfirmDialog, Dialog } from "../../ui/Dialog";
import { toast } from "../../ui/toasts";
import { PASSWORD_RULES, passwordProblem } from "./domainRules";

const useDomainUsers = () => useQuery({ queryKey: ["domain", "users"], queryFn: () => unwrap(api.GET("/domain/users")).then((r) => r.users) });
const useDomainGroups = () => useQuery({ queryKey: ["domain", "groups"], queryFn: () => unwrap(api.GET("/domain/groups")).then((r) => r.groups) });

function useRefreshDirectory() {
  const qc = useQueryClient();
  return () => {
    void qc.invalidateQueries({ queryKey: ["domain", "users"] });
    void qc.invalidateQueries({ queryKey: ["domain", "groups"] });
  };
}

/** Groups people pick for family members: their own, plus Domain Admins. */
function pickableGroups(groups: DomainGroup[]): DomainGroup[] {
  return groups.filter((g) => !g.builtin || g.name === "Domain Admins");
}

// ---- users -------------------------------------------------------------

export function DomainUsers() {
  const users = useDomainUsers();
  const refresh = useRefreshDirectory();
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<DomainUser | null>(null);
  const [resetting, setResetting] = useState<DomainUser | null>(null);
  const [deleting, setDeleting] = useState<DomainUser | null>(null);
  const [showBuiltin, setShowBuiltin] = useState(false);
  const toggle = useMutation({
    mutationFn: (u: DomainUser) => unwrap(api.PUT("/domain/users/{username}/enabled", { params: { path: { username: u.username } }, body: { enabled: !u.enabled } })),
    onSuccess: (u) => {
      refresh();
      toast("success", u.enabled ? `${u.username} can sign in again` : `${u.username} is turned off`);
    },
    onError: (e) => toast("error", "Couldn't change the account", errorMessage(e)),
  });

  if (users.isPending) return <Loading />;
  if (users.isError) return <ErrorBox error={users.error} onRetry={() => users.refetch()} />;
  const list = users.data.filter((u) => showBuiltin || !u.builtin);
  const people = users.data.filter((u) => !u.builtin);

  return (
    <>
      <div className="row row--between">
        <Toggle label="Show built-in accounts" checked={showBuiltin} onChange={setShowBuiltin} />
        <Button variant="primary" onClick={() => setCreating(true)}>
          <PlusIcon size={16} /> New account
        </Button>
      </div>
      {people.length === 0 && !showBuiltin ? (
        <Card>
          <EmptyState
            icon={<UsersIcon size={30} />}
            title="No accounts yet"
            action={
              <Button variant="primary" onClick={() => setCreating(true)}>
                Add the first account
              </Button>
            }
          >
            Give each family member their own account. They use it to sign in to Windows PCs in the domain and, later, to the NAS's shared
            folders and apps.
          </EmptyState>
        </Card>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Account</th>
                <th>Groups</th>
                <th>Status</th>
                <th>Last sign-in</th>
                <th className="actions">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {list.map((u) => (
                <tr key={u.username}>
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
                  <td className="small">{u.groups.filter((g) => g !== "Domain Users").join(", ") || <span className="muted">None</span>}</td>
                  <td>
                    <div className="row">
                      {u.enabled ? <Badge tone="good">Active</Badge> : <Badge tone="warn">Turned off</Badge>}
                      {u.lockedOut && <Badge tone="bad">Locked out</Badge>}
                      {u.mustChangePassword && <Badge tone="info">New password at next sign-in</Badge>}
                      {u.builtin && <Badge tone="neutral">Built in</Badge>}
                    </div>
                  </td>
                  <td>{u.lastLogon ? relativeTime(new Date(u.lastLogon * 1000).toISOString()) : <span className="muted">Never</span>}</td>
                  <td className="actions">
                    <IconButton label={`Edit ${u.username}`} onClick={() => setEditing(u)} disabled={u.builtin && u.username !== "Administrator"}>
                      <EditIcon size={16} />
                    </IconButton>
                    <IconButton label={`Set a new password for ${u.username}`} onClick={() => setResetting(u)} disabled={u.username === "Guest"}>
                      <KeyIcon size={16} />
                    </IconButton>
                    <IconButton label={`Delete ${u.username}`} onClick={() => setDeleting(u)} disabled={u.builtin}>
                      <TrashIcon size={16} />
                    </IconButton>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {creating && <NewUserDialog onClose={() => setCreating(false)} />}
      {editing && (
        <EditUserDialog
          user={editing}
          onToggle={() => toggle.mutate(editing)}
          toggleBusy={toggle.isPending}
          onClose={() => setEditing(null)}
        />
      )}
      {resetting && <ResetDialog user={resetting} onClose={() => setResetting(null)} />}
      {deleting && (
        <ConfirmDialog
          title={`Delete ${deleting.username}?`}
          confirmLabel="Delete account"
          onClose={() => setDeleting(null)}
          onConfirm={async () => {
            await unwrap(api.DELETE("/domain/users/{username}", { params: { path: { username: deleting.username } } }));
            refresh();
            toast("success", `Deleted ${deleting.username}`);
          }}
        >
          <p>
            <strong>{deleting.displayName || deleting.username}</strong> can't sign in anywhere in the domain anymore. To keep the account but stop
            sign-ins, turn it off instead.
          </p>
        </ConfirmDialog>
      )}
    </>
  );
}

function GroupPicker({ groups, selected, onChange }: { groups: DomainGroup[]; selected: string[]; onChange: (g: string[]) => void }) {
  if (groups.length === 0) return <p className="small muted" style={{ margin: 0 }}>No groups yet; make some on the Groups tab.</p>;
  return (
    <div className="check-list">
      {groups.map((g) => (
        <label key={g.name}>
          <input
            type="checkbox"
            checked={selected.includes(g.name)}
            onChange={(e) => onChange(e.target.checked ? [...selected, g.name] : selected.filter((x) => x !== g.name))}
          />
          <span>{g.name}</span>
        </label>
      ))}
    </div>
  );
}

function NewUserDialog({ onClose }: { onClose: () => void }) {
  const refresh = useRefreshDirectory();
  const groups = useDomainGroups();
  const [username, setUsername] = useState("");
  const [givenName, setGivenName] = useState("");
  const [surname, setSurname] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [mustChange, setMustChange] = useState(false);
  const [picked, setPicked] = useState<string[]>([]);
  const userProblem = username && !/^[A-Za-z0-9][A-Za-z0-9._-]{0,19}$/.test(username) ? "1 to 20 letters, digits, dots, dashes or underscores." : null;
  const pProblem = passwordProblem(password, username);
  const ready = username !== "" && !userProblem && password !== "" && !pProblem;

  const create = useMutation({
    mutationFn: () =>
      unwrap(
        api.POST("/domain/users", {
          body: { username, givenName, surname, email: email || undefined, password, mustChangePassword: mustChange, groups: picked },
        }),
      ),
    onSuccess: (u) => {
      refresh();
      toast("success", `Created ${u.username}`);
      onClose();
    },
  });

  return (
    <Dialog
      title="New account"
      width={560}
      onClose={onClose}
      onSubmit={() => ready && create.mutate()}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" busy={create.isPending} disabled={!ready}>
            Create account
          </Button>
        </>
      }
    >
      <div className="stack">
        <div className="grid-2">
          <Field label="First name">{(id) => <TextInput id={id} value={givenName} onChange={(e) => setGivenName(e.target.value)} />}</Field>
          <Field label="Last name">{(id) => <TextInput id={id} value={surname} onChange={(e) => setSurname(e.target.value)} />}</Field>
        </div>
        <Field label="Username" error={userProblem} hint="What they type to sign in. Can't be changed later.">
          {(id) => <TextInput id={id} value={username} onChange={(e) => setUsername(e.target.value.trim())} autoCapitalize="none" spellCheck={false} />}
        </Field>
        <Field label="Email" hint="Optional">
          {(id) => <TextInput id={id} type="email" value={email} onChange={(e) => setEmail(e.target.value)} />}
        </Field>
        <Field label="Password" error={pProblem} hint={PASSWORD_RULES}>
          {(id) => <TextInput id={id} type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" />}
        </Field>
        <Toggle label="Choose a new password at first sign-in" checked={mustChange} onChange={setMustChange} />
        <div className="field">
          <span className="field__label">Groups</span>
          {groups.data ? <GroupPicker groups={pickableGroups(groups.data)} selected={picked} onChange={setPicked} /> : <Loading />}
        </div>
        {create.error && <Alert tone="bad">{errorMessage(create.error)}</Alert>}
      </div>
    </Dialog>
  );
}

function EditUserDialog({ user, onToggle, toggleBusy, onClose }: { user: DomainUser; onToggle: () => void; toggleBusy: boolean; onClose: () => void }) {
  const refresh = useRefreshDirectory();
  const groups = useDomainGroups();
  const [givenName, setGivenName] = useState(user.givenName);
  const [surname, setSurname] = useState(user.surname);
  const [email, setEmail] = useState(user.email);
  const [picked, setPicked] = useState<string[]>(user.groups);

  const save = useMutation({
    mutationFn: async () => {
      const u = await unwrap(
        api.PATCH("/domain/users/{username}", { params: { path: { username: user.username } }, body: { givenName, surname, email } }),
      );
      const pickable = new Set(pickableGroups(groups.data ?? []).map((g) => g.name));
      const add = picked.filter((g) => pickable.has(g) && !user.groups.includes(g));
      const remove = user.groups.filter((g) => pickable.has(g) && !picked.includes(g));
      for (const g of add) await unwrap(api.PATCH("/domain/groups/{name}", { params: { path: { name: g } }, body: { add: [user.username] } }));
      for (const g of remove) await unwrap(api.PATCH("/domain/groups/{name}", { params: { path: { name: g } }, body: { remove: [user.username] } }));
      return u;
    },
    onSuccess: (u) => {
      refresh();
      toast("success", `Saved ${u.username}`);
      onClose();
    },
    onError: () => refresh(),
  });

  return (
    <Dialog
      title={`Edit ${user.username}`}
      width={560}
      onClose={onClose}
      onSubmit={() => save.mutate()}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" busy={save.isPending}>
            Save
          </Button>
        </>
      }
    >
      <div className="stack">
        <div className="grid-2">
          <Field label="First name">{(id) => <TextInput id={id} value={givenName} onChange={(e) => setGivenName(e.target.value)} />}</Field>
          <Field label="Last name">{(id) => <TextInput id={id} value={surname} onChange={(e) => setSurname(e.target.value)} />}</Field>
        </div>
        <Field label="Email">{(id) => <TextInput id={id} type="email" value={email} onChange={(e) => setEmail(e.target.value)} />}</Field>
        <div className="field">
          <span className="field__label">Groups</span>
          {groups.data ? <GroupPicker groups={pickableGroups(groups.data)} selected={picked} onChange={setPicked} /> : <Loading />}
        </div>
        {user.username !== "Administrator" && (
          <div className="row row--between">
            <span className="small muted">
              {user.enabled ? "Turned-off accounts keep everything but can't sign in." : "This account is turned off and can't sign in."}
            </span>
            <Button size="sm" onClick={onToggle} busy={toggleBusy}>
              {user.enabled ? "Turn off" : "Turn on"}
            </Button>
          </div>
        )}
        {save.error && <Alert tone="bad">{errorMessage(save.error)}</Alert>}
      </div>
    </Dialog>
  );
}

function ResetDialog({ user, onClose }: { user: DomainUser; onClose: () => void }) {
  const refresh = useRefreshDirectory();
  const [password, setPassword] = useState("");
  const [mustChange, setMustChange] = useState(true);
  const problem = passwordProblem(password, user.username);
  const reset = useMutation({
    mutationFn: () =>
      unwrap(api.POST("/domain/users/{username}/password", { params: { path: { username: user.username } }, body: { password, mustChangePassword: mustChange } })),
    onSuccess: () => {
      refresh();
      toast("success", `New password set for ${user.username}`);
      onClose();
    },
  });
  return (
    <Dialog
      title={`New password for ${user.username}`}
      description="This also unlocks the account if too many wrong passwords locked it."
      onClose={onClose}
      onSubmit={() => password && !problem && reset.mutate()}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" busy={reset.isPending} disabled={!password || !!problem}>
            Set password
          </Button>
        </>
      }
    >
      <div className="stack">
        <Field label="New password" error={problem} hint={PASSWORD_RULES}>
          {(id) => <TextInput id={id} type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" />}
        </Field>
        {user.username !== "Administrator" && (
          <Toggle label="Choose their own password at next sign-in" checked={mustChange} onChange={setMustChange} />
        )}
        {reset.error && <Alert tone="bad">{errorMessage(reset.error)}</Alert>}
      </div>
    </Dialog>
  );
}

// ---- groups ------------------------------------------------------------

export function DomainGroups() {
  const groups = useDomainGroups();
  const users = useDomainUsers();
  const refresh = useRefreshDirectory();
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<DomainGroup | null>(null);
  const [deleting, setDeleting] = useState<DomainGroup | null>(null);
  const [showBuiltin, setShowBuiltin] = useState(false);

  if (groups.isPending || users.isPending) return <Loading />;
  if (groups.isError) return <ErrorBox error={groups.error} onRetry={() => groups.refetch()} />;
  if (users.isError) return <ErrorBox error={users.error} onRetry={() => users.refetch()} />;
  const list = groups.data.filter((g) => showBuiltin || pickableGroups([g]).length > 0);

  return (
    <>
      <div className="row row--between">
        <Toggle label="Show built-in groups" checked={showBuiltin} onChange={setShowBuiltin} />
        <Button variant="primary" onClick={() => setCreating(true)}>
          <PlusIcon size={16} /> New group
        </Button>
      </div>
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Group</th>
              <th>Members</th>
              <th className="actions">
                <span className="sr-only">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {list.map((g) => (
              <tr key={g.name}>
                <td>
                  <strong>{g.name}</strong>
                  {g.name === "Domain Admins" ? (
                    <span className="cell-sub">Can manage the domain and every computer in it</span>
                  ) : (
                    g.description && <span className="cell-sub">{g.description}</span>
                  )}
                </td>
                <td className="small">{g.members.join(", ") || <span className="muted">Nobody yet</span>}</td>
                <td className="actions">
                  <IconButton label={`Edit ${g.name}`} onClick={() => setEditing(g)}>
                    <EditIcon size={16} />
                  </IconButton>
                  <IconButton label={`Delete ${g.name}`} onClick={() => setDeleting(g)} disabled={g.builtin}>
                    <TrashIcon size={16} />
                  </IconButton>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {creating && <GroupDialog users={users.data} onClose={() => setCreating(false)} />}
      {editing && <GroupDialog group={editing} users={users.data} onClose={() => setEditing(null)} />}
      {deleting && (
        <ConfirmDialog
          title={`Delete ${deleting.name}?`}
          confirmLabel="Delete group"
          onClose={() => setDeleting(null)}
          onConfirm={async () => {
            await unwrap(api.DELETE("/domain/groups/{name}", { params: { path: { name: deleting.name } } }));
            refresh();
            toast("success", `Deleted ${deleting.name}`);
          }}
        >
          <p>The group goes away; its members keep their accounts. Folders shared with this group stop being shared with them.</p>
        </ConfirmDialog>
      )}
    </>
  );
}

function GroupDialog({ group, users, onClose }: { group?: DomainGroup; users: DomainUser[]; onClose: () => void }) {
  const refresh = useRefreshDirectory();
  const [name, setName] = useState(group?.name ?? "");
  const [description, setDescription] = useState(group?.description ?? "");
  const [members, setMembers] = useState<string[]>(group?.members ?? []);
  const people = users.filter((u) => !u.builtin || u.username === "Administrator" || members.includes(u.username));
  const nameProblem = name && !/^[A-Za-z0-9]([A-Za-z0-9 ._-]{0,62}[A-Za-z0-9._-])?$/.test(name) ? "Up to 64 letters, digits, spaces, dots, dashes or underscores." : null;

  const save = useMutation({
    mutationFn: () => {
      if (!group) return unwrap(api.POST("/domain/groups", { body: { name: name.trim(), description, members } }));
      const add = members.filter((m) => !group.members.includes(m));
      const remove = group.members.filter((m) => !members.includes(m));
      return unwrap(
        api.PATCH("/domain/groups/{name}", {
          params: { path: { name: group.name } },
          body: { description: group.builtin ? undefined : description, add, remove },
        }),
      );
    },
    onSuccess: (g) => {
      refresh();
      toast("success", group ? `Saved ${g.name}` : `Created ${g.name}`);
      onClose();
    },
  });

  return (
    <Dialog
      title={group ? `Edit ${group.name}` : "New group"}
      width={560}
      onClose={onClose}
      onSubmit={() => name && !nameProblem && save.mutate()}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" busy={save.isPending} disabled={!name || !!nameProblem}>
            {group ? "Save" : "Create group"}
          </Button>
        </>
      }
    >
      <div className="stack">
        {!group && (
          <Field label="Name" error={nameProblem} hint="For example Family, Kids or Media.">
            {(id) => <TextInput id={id} value={name} onChange={(e) => setName(e.target.value)} />}
          </Field>
        )}
        {!group?.builtin && (
          <Field label="Description" hint="Optional">
            {(id) => <TextInput id={id} value={description} onChange={(e) => setDescription(e.target.value)} />}
          </Field>
        )}
        <div className="field">
          <span className="field__label">Members</span>
          {people.length === 0 ? (
            <p className="small muted" style={{ margin: 0 }}>No accounts yet; add some on the Users tab.</p>
          ) : (
            <div className="check-list">
              {people.map((u) => (
                <label key={u.username}>
                  <input
                    type="checkbox"
                    checked={members.includes(u.username)}
                    disabled={group?.name === "Domain Admins" && u.username === "Administrator"}
                    onChange={(e) => setMembers(e.target.checked ? [...members, u.username] : members.filter((m) => m !== u.username))}
                  />
                  <span title={u.displayName}>{u.displayName || u.username}</span>
                </label>
              ))}
            </div>
          )}
        </div>
        {save.error && <Alert tone="bad">{errorMessage(save.error)}</Alert>}
      </div>
    </Dialog>
  );
}
