import type { FileServicesStatus } from "@hardy/api-client";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api, errorMessage, unwrap } from "../../api";
import { Alert, Badge, Card, Toggle } from "../../ui";
import { toast } from "../../ui/toasts";
import { davURL, davWindowsPath, rcloneConfig, sftpCommand, sftpURL } from "./remoteRules";
import { jobDone } from "./shareServices";

/** File Services: SFTP and WebDAV on or off for the whole server, and how to connect. */
export function RemoteAccessCard({ st, admin }: { st: FileServicesStatus; admin: boolean }) {
  const qc = useQueryClient();
  const set = useMutation({
    mutationFn: (body: { sftpEnabled?: boolean; sftpAdmins?: boolean; webdavEnabled?: boolean }) =>
      jobDone(unwrap(api.PATCH("/files/settings", { body }))),
    onSuccess: (_, body) => {
      if (body.sftpAdmins !== undefined) {
        toast("success", `Domain administrators ${body.sftpAdmins ? "can" : "can't"} use SFTP`);
      } else {
        const what = body.sftpEnabled !== undefined ? "SFTP" : "WebDAV";
        toast("success", `${what} is ${(body.sftpEnabled ?? body.webdavEnabled) ? "on" : "off"}`);
      }
      void qc.invalidateQueries({ queryKey: ["files"] });
    },
  });
  const nb = st.domain?.netbios ?? "HOME";
  const sshHost = st.hostName || st.addresses[0] || st.serverName.toLowerCase();
  const webHost = typeof window !== "undefined" ? window.location.host : st.hostName;
  const sftpFolders = st.shares.filter((s) => s.sftp).map((s) => s.name);
  const davFolders = st.shares.filter((s) => s.webdav).map((s) => s.name);
  const sftp = st.sftp;
  const homes = st.settings.homes.enabled ? " and their Home folder" : "";

  return (
    <Card title="SFTP and WebDAV">
      <div className="stack">
        <span className="small muted">
          For domain accounts, from anywhere this server can be reached (at home, or over the VPN). Each folder has its own switches too (Shared Folders ›
          Edit › SFTP and WebDAV), off for new folders; who can use what follows the folder's rules.
        </span>
        {admin && (
          <Toggle
            label="SFTP"
            description="Domain accounts can sign in with their domain password and use only SFTP, inside their own view of the folders they may use. They never get a shell or tunnels; SSH for this server's own Linux accounts is unchanged."
            checked={st.settings.sftpEnabled}
            disabled={set.isPending}
            onChange={(v) => set.mutate({ sftpEnabled: v })}
          />
        )}
        {admin && st.settings.sftpEnabled && sftp && (
          <div className="row" style={{ gap: 6 }}>
            {sftp.running ? <Badge tone="good">SSH server running</Badge> : <Badge tone="warn">SSH server not running</Badge>}
            <Badge tone="neutral">
              <span className="mono">{sftp.users}</span>&nbsp;accounts with folders
            </Badge>
          </div>
        )}
        {admin && st.settings.sftpEnabled && (
          <Toggle
            label="Domain administrators too"
            description="Off: members of Domain Admins and HardyOS Admins get no SFTP view, so their passwords are never tried over SSH. Turn on only if they need SFTP."
            checked={st.settings.sftpAdmins ?? false}
            disabled={set.isPending}
            onChange={(v) => set.mutate({ sftpAdmins: v })}
          />
        )}
        {admin && st.settings.sftpEnabled && sftp?.problem && <Alert tone="warn">{sftp.problem}</Alert>}
        {admin && (
          <Toggle
            label="WebDAV"
            description="Domain accounts can open the folders at the address below over HTTPS, signing in with their domain password."
            checked={st.settings.webdavEnabled}
            disabled={set.isPending}
            onChange={(v) => set.mutate({ webdavEnabled: v })}
          />
        )}
        {set.isError && <Alert tone="bad">{errorMessage(set.error)}</Alert>}

        {st.settings.sftpEnabled && (
          <div className="stack" style={{ gap: 4 }}>
            <strong className="small">SFTP</strong>
            <span className="small">
              Server <span className="mono">{sshHost}</span>, port <span className="mono">{sftp?.port ?? 22}</span>, user{" "}
              <span className="mono">{nb}\yourname</span> and your domain password. In WinSCP, FileZilla or Cyberduck choose SFTP; Mac and Linux file
              managers open <span className="mono">{sftpURL(sshHost, nb)}</span>. From a terminal:
            </span>
            <pre className="log-view" aria-label="SFTP command">
              {sftpCommand(sshHost, nb)}
            </pre>
            <span className="small muted">
              {sftpFolders.length > 0 ? (
                <>
                  Folders: <span className="mono">{sftpFolders.join(", ")}</span>
                  {homes}, each person seeing only the ones they may use.
                </>
              ) : (
                `No shared folder has SFTP on yet${homes ? "; people see their Home folder" : ""}.`
              )}
            </span>
          </div>
        )}
        {st.settings.webdavEnabled && (
          <div className="stack" style={{ gap: 4 }}>
            <strong className="small">WebDAV</strong>
            <span className="small">
              Address <span className="mono">{davURL(webHost)}</span>, user <span className="mono">{nb}\yourname</span>.
            </span>
            <span className="small">
              Windows: File Explorer › This PC › Map network drive, folder <span className="mono">{davWindowsPath(webHost)}</span> (the server's
              certificate must be trusted by the PC). Mac: Finder › Go › Connect to Server › <span className="mono">{davURL(webHost)}</span>. Linux file
              managers open <span className="mono">{davURL(webHost).replace("https://", "davs://")}</span>. rclone:
            </span>
            <pre className="log-view" aria-label="rclone command">
              {rcloneConfig(webHost, nb)}
            </pre>
            <span className="small muted">
              {davFolders.length > 0 ? (
                <>
                  Folders: <span className="mono">{davFolders.join(", ")}</span>
                  {homes}.
                </>
              ) : (
                `No shared folder has WebDAV on yet${homes ? "; people see their Home folder" : ""}.`
              )}
            </span>
          </div>
        )}
      </div>
    </Card>
  );
}
