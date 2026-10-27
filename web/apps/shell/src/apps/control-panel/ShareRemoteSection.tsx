import type { Share } from "@hardy/api-client";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { errorMessage } from "../../api";
import { Alert, Button, Toggle } from "../../ui";
import { toast } from "../../ui/toasts";
import { davURL, sftpURL } from "./remoteRules";
import { useFileServices } from "./ShareSMBSection";
import { saveServices } from "./shareServices";

/** Shared folder dialog: SFTP and WebDAV (remote file access for domain accounts). */
export function ShareRemoteSection({ share }: { share?: Share }) {
  if (!share) {
    return (
      <div className="stack" style={{ gap: 6 }}>
        <strong className="small">SFTP and WebDAV</strong>
        <span className="small muted">Off for new folders. Turn them on here once the folder is made.</span>
      </div>
    );
  }
  return <Remote share={share} />;
}

function Remote({ share }: { share: Share }) {
  const qc = useQueryClient();
  const files = useFileServices();
  const [base, setBase] = useState({ sftp: share.services?.sftp ?? false, webdav: share.services?.webdav ?? false });
  const [sftp, setSftp] = useState(base.sftp);
  const [webdav, setWebdav] = useState(base.webdav);
  const changed = sftp !== base.sftp || webdav !== base.webdav;

  const save = useMutation({
    mutationFn: () => saveServices(share.id, (s) => ({ ...s, sftp, webdav })),
    onSuccess: (sh) => {
      toast("success", "SFTP and WebDAV settings saved");
      setBase({ sftp: sh.services.sftp, webdav: sh.services.webdav });
      void qc.invalidateQueries({ queryKey: ["shares"] });
      void qc.invalidateQueries({ queryKey: ["files"] });
    },
  });

  const st = files.data;
  const nb = st?.domain?.netbios ?? "HOME";
  const sshHost = st?.hostName || (typeof window !== "undefined" ? window.location.hostname : "hardyos");
  const webHost = typeof window !== "undefined" ? window.location.host : "hardyos";

  return (
    <div className="stack" style={{ gap: 10 }}>
      <strong className="small">SFTP and WebDAV</strong>
      <Toggle
        label="SFTP"
        description="Domain accounts can open it with an SFTP app (WinSCP, Cyberduck, FileZilla) or from a terminal. Who can use it follows the rules above."
        checked={sftp}
        onChange={setSftp}
      />
      <Toggle
        label="WebDAV"
        description="Domain accounts can open it over HTTPS as a network drive (Windows, Finder) or with apps like rclone."
        checked={webdav}
        onChange={setWebdav}
      />
      {changed && (
        <div className="row">
          <Button size="sm" variant="primary" busy={save.isPending} onClick={() => save.mutate()}>
            Save SFTP and WebDAV settings
          </Button>
          <Button
            size="sm"
            onClick={() => {
              setSftp(base.sftp);
              setWebdav(base.webdav);
            }}
          >
            Undo
          </Button>
        </div>
      )}
      {save.isError && <Alert tone="bad">{errorMessage(save.error)}</Alert>}
      {!changed && st && (base.sftp || base.webdav) && (
        <div className="stack" style={{ gap: 6 }}>
          {!st.joined && <span className="small muted">Offered once this server joins the domain (Control Panel › File Services).</span>}
          {st.joined && base.sftp && (
            <span className="small">
              SFTP:{" "}
              {st.settings.sftpEnabled ? (
                <span className="mono">{sftpURL(sshHost, nb, share.name)}</span>
              ) : (
                <span className="muted">turned off for the whole server in File Services.</span>
              )}
            </span>
          )}
          {st.joined && base.webdav && (
            <span className="small">
              WebDAV:{" "}
              {st.settings.webdavEnabled ? (
                <span className="mono">{davURL(webHost, share.name)}</span>
              ) : (
                <span className="muted">turned off for the whole server in File Services.</span>
              )}
            </span>
          )}
        </div>
      )}
    </div>
  );
}
