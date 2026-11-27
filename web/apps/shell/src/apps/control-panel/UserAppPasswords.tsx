import type { AppPassword, User } from "@hardy/api-client";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, unwrap } from "../../api";
import { SCOPE_LABELS } from "../../auth/twoFactorRules";
import { dateTime, relativeTime } from "../../format";
import { KeyIcon, TrashIcon } from "../../icons";
import { Alert, Button, ErrorBox, IconButton, Loading } from "../../ui";
import { ConfirmDialog, Dialog } from "../../ui/Dialog";
import { toast } from "../../ui/toasts";

/** "used 3 days ago from 203.0.113.9" or "never used". */
export function lastUsedText(p: Pick<AppPassword, "lastUsedAt" | "lastUsedIp">, rel: (s: string) => string = relativeTime): string {
  if (!p.lastUsedAt) return "never used";
  return `used ${rel(p.lastUsedAt)}${p.lastUsedIp ? ` from ${p.lastUsedIp}` : ""}`;
}

/**
 * Users & Groups › App passwords: an administrator sees a domain account's
 * app passwords (one per device: scopes, made, last used and from where)
 * and revokes them one by one (decision 517; audited by hardyd).
 */
export function UserAppPasswordsDialog({ user, onClose }: { user: User; onClose: () => void }) {
  const qc = useQueryClient();
  const key = ["user-app-passwords", user.id];
  const list = useQuery({ queryKey: key, queryFn: () => unwrap(api.GET("/users/{id}/app-passwords", { params: { path: { id: user.id } } })) });
  const [revoking, setRevoking] = useState<AppPassword | null>(null);
  const who = user.displayName || user.username;

  if (revoking) {
    return (
      <ConfirmDialog
        title={`Revoke ${revoking.name}?`}
        confirmLabel="Revoke"
        onClose={() => setRevoking(null)}
        onConfirm={async () => {
          await unwrap(api.DELETE("/users/{id}/app-passwords/{pid}", { params: { path: { id: user.id, pid: revoking.id } } }));
          await qc.invalidateQueries({ queryKey: key });
          toast("success", `Revoked ${revoking.name}`, `${who}'s device using it stops signing in at once.`);
        }}
      >
        <p>
          The device or app <strong>{revoking.name}</strong> stops signing in to {revoking.scopes.map((s) => SCOPE_LABELS[s]).join(", ")} for{" "}
          <strong>{who}</strong> at once. They can make a new one themselves. This is recorded in the audit log.
        </p>
      </ConfirmDialog>
    );
  }

  return (
    <Dialog
      title={`App passwords of ${user.username}`}
      description="One per device, for mail, WebDAV, SFTP and calendar apps that can't ask for a two-factor code. Revoke one when a device is lost or no longer used."
      onClose={onClose}
      width={560}
      footer={
        <Button variant="primary" onClick={onClose}>
          Done
        </Button>
      }
    >
      {list.isPending ? (
        <Loading />
      ) : list.isError ? (
        <ErrorBox error={list.error} onRetry={() => list.refetch()} />
      ) : list.data.length === 0 ? (
        <Alert tone="info">{who} has no app passwords.</Alert>
      ) : (
        <ul className="tfa-applist" aria-label={`App passwords of ${user.username}`}>
          {list.data.map((p) => (
            <li key={p.id}>
              <KeyIcon size={16} />
              <div>
                <strong>{p.name}</strong>
                <span className="cell-sub">{p.scopes.map((s) => SCOPE_LABELS[s]).join(" · ")}</span>
                <span className="cell-sub">
                  <span title={dateTime(p.createdAt)}>made {relativeTime(p.createdAt)}</span> ·{" "}
                  <span title={p.lastUsedAt ? dateTime(p.lastUsedAt) : undefined}>{lastUsedText(p)}</span>
                </span>
              </div>
              <IconButton label={`Revoke ${p.name}`} onClick={() => setRevoking(p)}>
                <TrashIcon size={16} />
              </IconButton>
            </li>
          ))}
        </ul>
      )}
    </Dialog>
  );
}
