import type { FileShare, ShareLink } from "@hardy/api-client";
import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, unwrap } from "../../api";
import { bytes, dateTime, relativeTime } from "../../format";
import { Badge, Button, EmptyState, ErrorBox, Loading, type Tone } from "../../ui";
import { ConfirmDialog } from "../../ui/Dialog";
import { toast } from "../../ui/toasts";
import { useShareLinks } from "./fileApi";
import { KindIcon, LinkIcon } from "./icons";
import { HOME } from "./paths";

const STATUS: Record<ShareLink["status"], { label: string; tone: Tone }> = {
  active: { label: "Active", tone: "good" },
  expired: { label: "Expired", tone: "neutral" },
  revoked: { label: "Turned off", tone: "neutral" },
  "used-up": { label: "Limit reached", tone: "warn" },
};

/** "Links I've shared", or every link on the server for administrators. */
export function SharedLinks({ scope, shares, onOpen }: { scope: "mine" | "all"; shares: FileShare[]; onOpen: (share: string, dir: string) => void }) {
  const q = useShareLinks(scope);
  const qc = useQueryClient();
  const [revoking, setRevoking] = useState<ShareLink | null>(null);
  const shareName = (id: string) => (id === HOME ? "Home" : (shares.find((s) => s.id === id)?.name ?? id));

  return (
    <div className="fm-links">
      <header className="fm-links__head">
        <h2>{scope === "all" ? "All share links" : "Links I've shared"}</h2>
        <p className="small muted">
          {scope === "all"
            ? "Every link anyone on this server has made. Turning one off stops it straight away."
            : "Links you made to files and folders. A link stops when it expires, when you turn it off, or if you lose access to what it points at."}
        </p>
      </header>
      {q.isPending ? (
        <Loading />
      ) : q.isError ? (
        <ErrorBox error={q.error} onRetry={() => q.refetch()} />
      ) : q.data.length === 0 ? (
        <EmptyState icon={<LinkIcon size={28} />} title="No links yet">
          Select a file or folder and choose Share link to make one.
        </EmptyState>
      ) : (
        <div className="table-wrap">
          <table className="table fm-links__table">
            <thead>
              <tr>
                <th>Shared</th>
                {scope === "all" && <th>By</th>}
                <th>Status</th>
                <th className="fm-hide-narrow">Expires</th>
                <th className="num fm-hide-narrow">Downloads</th>
                <th className="actions" aria-label="Actions" />
              </tr>
            </thead>
            <tbody>
              {q.data.map((l) => {
                const st = STATUS[l.status];
                const where = l.path ? `${shareName(l.share)} / ${l.path}` : shareName(l.share);
                return (
                  <tr key={l.id}>
                    <td>
                      <button
                        type="button"
                        className="fm-links__target"
                        title={`Show in ${shareName(l.share)}`}
                        onClick={() => onOpen(l.share, l.dir ? l.path : l.path.slice(0, Math.max(0, l.path.lastIndexOf("/"))))}
                      >
                        <KindIcon kind={l.dir ? "folder" : "file"} size={16} />
                        <span className="fm-ellipsis">{l.name || shareName(l.share)}</span>
                      </button>
                      <span className="cell-sub">
                        {where}
                        {l.hasPassword ? " · password" : ""}
                        {l.allowUpload ? ` · uploads on (${bytes(l.uploadedBytes)} of ${bytes(l.maxUploadBytes)})` : ""}
                      </span>
                    </td>
                    {scope === "all" && <td>{l.createdBy}</td>}
                    <td>
                      <Badge tone={st.tone}>{st.label}</Badge>
                    </td>
                    <td className="fm-hide-narrow" title={dateTime(l.expiresAt)}>
                      {l.status === "active" ? relativeTime(l.expiresAt) : "–"}
                    </td>
                    <td className="num mono fm-hide-narrow">
                      {l.downloadCount}
                      {l.maxDownloads ? ` / ${l.maxDownloads}` : ""}
                    </td>
                    <td className="actions">
                      {!l.revoked && l.status !== "expired" && (
                        <Button size="sm" variant="ghost" onClick={() => setRevoking(l)} aria-label={`Turn off the link to ${l.name || shareName(l.share)}`}>
                          Turn off
                        </Button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {revoking && (
        <ConfirmDialog
          title="Turn off this link?"
          confirmLabel="Turn off"
          onClose={() => setRevoking(null)}
          onConfirm={async () => {
            await unwrap(api.POST("/sharelinks/{id}/revoke", { params: { path: { id: revoking.id } } }));
            toast("success", "Link turned off");
            await qc.invalidateQueries({ queryKey: ["sharelinks"] });
          }}
        >
          <p>
            The link to “{revoking.name || shareName(revoking.share)}” stops working straight away for everyone who has it. The files themselves stay where they
            are.
          </p>
        </ConfirmDialog>
      )}
    </div>
  );
}
