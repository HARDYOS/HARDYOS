import type { Share } from "@hardy/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, errorMessage, unwrap } from "../../api";
import { Alert, Badge, Button, Field, Select, TextInput, Toggle } from "../../ui";
import { toast } from "../../ui/toasts";
import { smbPath, tmSizeFields, tmSizeBytes, type TmUnit } from "./fileServicesRules";
import { DEFAULT_SERVICES, saveServices } from "./shareServices";

export const useFileServices = () => useQuery({ queryKey: ["files"], queryFn: () => unwrap(api.GET("/files")), staleTime: 15_000 });

/** Shared folder dialog: SMB (Windows and Macs), Time Machine and Previous Versions. */
export function ShareSMBSection({ share }: { share?: Share }) {
  if (!share) {
    return (
      <div className="stack" style={{ gap: 6 }}>
        <strong className="small">Windows and Mac file sharing (SMB)</strong>
        <span className="small muted">On for new folders, with Previous Versions. Time Machine can be turned on here once the folder is made.</span>
      </div>
    );
  }
  return <SMB share={share} />;
}

function SMB({ share }: { share: Share }) {
  const qc = useQueryClient();
  const files = useFileServices();
  const saved = share.services?.smb ?? DEFAULT_SERVICES.smb;
  const [base, setBase] = useState(saved);
  const [enabled, setEnabled] = useState(saved.enabled);
  const [previous, setPrevious] = useState(saved.previousVersions);
  const [tm, setTm] = useState(saved.timeMachine);
  const t = tmSizeFields(saved.timeMachineMaxBytes);
  const [size, setSize] = useState(t.value);
  const [unit, setUnit] = useState<TmUnit>(t.unit);
  const tmBytes = tmSizeBytes(size, unit);
  const sizeProblem = tmBytes === null ? "Enter a number, or leave it empty to use the folder's quota." : null;
  const changed =
    enabled !== base.enabled || previous !== base.previousVersions || tm !== base.timeMachine || (tm && (tmBytes ?? -1) !== base.timeMachineMaxBytes);

  const save = useMutation({
    mutationFn: () =>
      saveServices(share.id, (s) => ({
        ...s,
        smb: { enabled, previousVersions: enabled && previous, timeMachine: enabled && tm, timeMachineMaxBytes: enabled && tm ? (tmBytes ?? 0) : 0 },
      })),
    onSuccess: (sh) => {
      toast("success", sh.services.smb.enabled ? `${share.name} is shared with Windows and Macs` : "SMB settings saved");
      setBase(sh.services.smb);
      void qc.invalidateQueries({ queryKey: ["shares"] });
      void qc.invalidateQueries({ queryKey: ["files"] });
    },
  });

  const st = files.data;
  const info = st?.shares.find((s) => s.id === share.id);
  const server = st?.serverName || "HARDYOS";

  return (
    <div className="stack" style={{ gap: 10 }}>
      <strong className="small">Windows and Mac file sharing (SMB)</strong>
      <Toggle
        label="Share with Windows PCs and Macs"
        description="People sign in with their domain account; who can use it follows the rules above."
        checked={enabled}
        onChange={(v) => {
          setEnabled(v);
          if (!v) setTm(false);
        }}
      />
      {enabled && (
        <>
          <Toggle
            label="Previous Versions"
            description="Windows shows this folder's automatic snapshots in a file's Properties › Previous Versions, so people can bring back older copies themselves."
            checked={previous}
            onChange={setPrevious}
          />
          <Toggle
            label="Time Machine"
            description="Macs on the network can back up here. Its recycle bin is off while Time Machine is on."
            checked={tm}
            onChange={setTm}
          />
          {tm && (
            <Field label="Most each Mac may use" error={sizeProblem} hint="Leave empty to let backups grow up to the folder's quota.">
              {(fid) => (
                <div className="row" style={{ flexWrap: "nowrap" }}>
                  <TextInput
                    id={fid}
                    className="input mono"
                    inputMode="decimal"
                    value={size}
                    onChange={(e) => setSize(e.target.value)}
                    placeholder="The folder's quota"
                    style={{ flex: 1 }}
                  />
                  <Select aria-label="Time Machine size unit" value={unit} onChange={(e) => setUnit(e.target.value as TmUnit)} style={{ width: 90 }}>
                    <option value="GB">GB</option>
                    <option value="TB">TB</option>
                  </Select>
                </div>
              )}
            </Field>
          )}
        </>
      )}
      {changed && (
        <div className="row">
          <Button size="sm" variant="primary" disabled={!!(tm && sizeProblem)} busy={save.isPending} onClick={() => save.mutate()}>
            Save SMB settings
          </Button>
          <Button
            size="sm"
            onClick={() => {
              setEnabled(base.enabled);
              setPrevious(base.previousVersions);
              setTm(base.timeMachine);
              const f = tmSizeFields(base.timeMachineMaxBytes);
              setSize(f.value);
              setUnit(f.unit);
            }}
          >
            Undo
          </Button>
        </div>
      )}
      {save.isError && <Alert tone="bad">{errorMessage(save.error)}</Alert>}
      {base.enabled && !changed && st && (
        <div className="stack" style={{ gap: 6 }}>
          {!st.joined ? (
            <span className="small muted">Shared once this server joins the domain (Control Panel › File Services).</span>
          ) : !st.settings.smbEnabled ? (
            <span className="small muted">SMB sharing is turned off for the whole server in File Services.</span>
          ) : (
            <>
              <div className="row" style={{ gap: 6 }}>
                {info?.available ? <Badge tone="good">Shared</Badge> : <Badge tone="warn">Not available right now</Badge>}
                {base.timeMachine && <Badge tone="info">Time Machine</Badge>}
              </div>
              <span className="small">
                Windows: <span className="mono">{smbPath("windows", server, share.name)}</span>
              </span>
              <span className="small">
                Mac (Finder › Go › Connect to Server): <span className="mono">{smbPath("mac", st.hostName || server.toLowerCase(), share.name)}</span>
              </span>
              {info && info.skipped.length > 0 && (
                <Alert tone="warn">
                  These rules don't apply over SMB: {info.skipped.join(", ")}. Only the domain's own users and groups can sign in.
                </Alert>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}
