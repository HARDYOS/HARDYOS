import type { User } from "@hardy/api-client";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { api, errorMessage, unwrap } from "../api";
import { dateTime, initials, relativeTime } from "../format";
import { useNotifications } from "../hooks/queries";
import { useUnread } from "../hooks/monitoring";
import { openLink } from "../links";
import { openApp } from "../wm/open";
import { useLogout } from "../hooks/session";
import { BrandMark } from "../brand";
import { BellIcon, KeyIcon, LogoutIcon } from "../icons";
import { APP_WINDOW, appById } from "../shell";
import { Alert, Button, Field, TextInput } from "../ui";
import { Dialog } from "../ui/Dialog";
import { toast } from "../ui/toasts";
import { useWM } from "../wm/store";

const clockFmt = new Intl.DateTimeFormat(undefined, { weekday: "short", month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });

function Clock() {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 15_000);
    return () => clearInterval(t);
  }, []);
  return (
    <time className="menubar__clock" dateTime={now.toISOString()} title={dateTime(now.toISOString())}>
      {clockFmt.format(now)}
    </time>
  );
}

/** Closes a popover when clicking outside it or pressing Escape. */
function usePopover() {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const onDown = (e: PointerEvent) => !ref.current?.contains(e.target as Node) && setOpen(false);
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    document.addEventListener("pointerdown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("pointerdown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);
  return { open, setOpen, ref };
}

function NotificationCenter({ user }: { user: User }) {
  const { open, setOpen, ref } = usePopover();
  const { data = [] } = useNotifications();
  const unreadQ = useUnread();
  const qc = useQueryClient();
  const unread = unreadQ.data?.count ?? data.filter((n) => !n.readAt).length;
  const refresh = () => qc.invalidateQueries({ queryKey: ["notifications"] });
  const readAll = useMutation({ mutationFn: () => unwrap(api.POST("/notifications/read-all")), onSuccess: refresh });
  const readOne = useMutation({
    mutationFn: (id: number) => unwrap(api.POST("/notifications/{id}/read", { params: { path: { id } } })),
    onSuccess: refresh,
  });
  const label = unread > 99 ? "99+" : String(unread);

  return (
    <div className="popover-anchor" ref={ref}>
      <button
        type="button"
        className="menubar__icon"
        aria-label={unread ? `Notifications, ${unread} unread` : "Notifications"}
        aria-expanded={open}
        onClick={() => setOpen(!open)}
      >
        <BellIcon size={16} />
        {unread > 0 && (
          <span className="menubar__count" aria-hidden="true">
            {label}
          </span>
        )}
      </button>
      {open && (
        <div className="popover popover--notifications glass" role="dialog" aria-label="Notifications">
          <div className="popover__head popover__head--row">
            <span>Notifications</span>
            {unread > 0 && (
              <button type="button" onClick={() => readAll.mutate()} disabled={readAll.isPending}>
                Mark all read
              </button>
            )}
          </div>
          {data.length === 0 ? (
            <p className="popover__empty">You're all caught up.</p>
          ) : (
            <ul className="notif-list">
              {data.map((n) => (
                <li key={n.id}>
                  <button
                    type="button"
                    className={`notif notif--button${n.readAt ? " notif--read" : ""}`}
                    onClick={() => {
                      if (!n.readAt) readOne.mutate(n.id);
                      if (openLink(n.link, user)) setOpen(false);
                    }}
                  >
                    <span className={`notif__bar notif__bar--${n.level}`} aria-hidden="true" />
                    <span className="notif__text">
                      <strong>
                        {n.title}
                        {!n.readAt && <span className="notif__unread" aria-label="unread" />}
                      </strong>
                      {n.body && <span>{n.body}</span>}
                      <time dateTime={n.at} title={dateTime(n.at)}>
                        {relativeTime(n.at)}
                      </time>
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          )}
          {user.role === "admin" && (
            <div className="popover__foot">
              <button
                type="button"
                onClick={() => {
                  setOpen(false);
                  openApp("os.hardy.control", user, { section: "notifications" });
                }}
              >
                Notification settings
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function ChangePasswordDialog({ onClose }: { onClose: () => void }) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const change = useMutation({
    mutationFn: () => unwrap(api.POST("/auth/password", { body: { currentPassword: current, newPassword: next } })),
    onSuccess: () => {
      toast("success", "Password changed", "Your other devices were signed out.");
      onClose();
    },
  });
  const mismatch = confirm.length > 0 && confirm !== next;
  return (
    <Dialog
      title="Change password"
      onClose={onClose}
      onSubmit={() => !mismatch && next.length >= 10 && change.mutate()}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" busy={change.isPending} disabled={mismatch || next.length < 10 || !current}>
            Change password
          </Button>
        </>
      }
    >
      <div className="stack">
        <Field label="Current password">
          {(id) => <TextInput id={id} type="password" value={current} onChange={(e) => setCurrent(e.target.value)} autoComplete="current-password" />}
        </Field>
        <Field label="New password" hint="At least 10 characters">
          {(id) => <TextInput id={id} type="password" value={next} onChange={(e) => setNext(e.target.value)} autoComplete="new-password" />}
        </Field>
        <Field label="Repeat new password" error={mismatch ? "Passwords don't match" : null}>
          {(id) => <TextInput id={id} type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="new-password" />}
        </Field>
        {change.error && <Alert tone="bad">{errorMessage(change.error)}</Alert>}
      </div>
    </Dialog>
  );
}

function UserMenu({ user }: { user: User }) {
  const { open, setOpen, ref } = usePopover();
  const [changing, setChanging] = useState(false);
  const logout = useLogout();
  const name = user.displayName || user.username;
  return (
    <div className="popover-anchor" ref={ref}>
      <button type="button" className="avatar avatar--sm" aria-label={`Account: ${name}`} aria-expanded={open} onClick={() => setOpen(!open)}>
        {initials(name)}
      </button>
      {open && (
        <div className="popover popover--menu glass" role="menu" aria-label="Account">
          <div className="popover__user">
            <span className="avatar">{initials(name)}</span>
            <div>
              <strong>{name}</strong>
              <span>
                {user.role === "admin" ? "Administrator" : "User"} · {user.username}
                {user.source === "domain" ? " · domain account" : ""}
              </span>
            </div>
          </div>
          {user.source === "domain" ? (
            <p className="menu-note small muted" style={{ margin: "4px 10px 6px", maxWidth: 240 }}>
              Your password belongs to the domain. Change it on a computer in the domain, or ask an administrator.
            </p>
          ) : (
            <button type="button" role="menuitem" className="menu-item" onClick={() => { setOpen(false); setChanging(true); }}>
              <KeyIcon size={16} /> Change password
            </button>
          )}
          <button type="button" role="menuitem" className="menu-item" onClick={() => logout.mutate()}>
            <LogoutIcon size={16} /> Sign out
          </button>
        </div>
      )}
      {changing && <ChangePasswordDialog onClose={() => setChanging(false)} />}
    </div>
  );
}

export function MenuBar({ user, connection }: { user: User; connection: string }) {
  const focusedApp = useWM((s) => {
    const w = s.windows.find((x) => x.id === s.focusedId);
    if (!w) return undefined;
    // An installed app's window is named after the app, not the window kind.
    return w.appId.startsWith(`${APP_WINDOW}:`) ? w.title : appById(w.appId)?.name;
  });
  return (
    <header className="menubar glass">
      <BrandMark size={18} label="HardyOS" />
      <span className="menubar__app">{focusedApp ?? "HardyOS"}</span>
      <span className="menubar__spacer" />
      {connection === "closed" && (
        <span className="menubar__offline" role="status">
          Reconnecting…
        </span>
      )}
      <NotificationCenter user={user} />
      <UserMenu user={user} />
      <Clock />
    </header>
  );
}
