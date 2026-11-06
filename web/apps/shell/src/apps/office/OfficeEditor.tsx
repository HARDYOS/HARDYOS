import type { OfficeOpened } from "@hardy/api-client";
import { useCallback, useEffect, useState } from "react";
import { errorMessage } from "../../api";
import { RefreshIcon } from "../../icons";
import type { AppProps } from "../../shell";
import { Alert, Badge, Button, Loading } from "../../ui";
import { openDocument } from "./officeApi";

/**
 * The editor: OnlyOffice in a desktop window. The page inside comes from
 * the office origin (its own port), with a one-minute single-use ticket
 * bound to this desktop session; the Document Server's scripts never run on
 * the desktop's origin.
 */
export const OFFICE_FRAME_SANDBOX = "allow-scripts allow-same-origin allow-forms allow-popups allow-popups-to-escape-sandbox allow-modals allow-downloads";

export default function OfficeEditor({ args }: AppProps) {
  const share = args?.share ?? "";
  const path = args?.path ?? "";
  const mode = args?.mode === "view" ? "view" : "edit";
  return <OfficeEditorView share={share} path={path} mode={mode} />;
}

export function OfficeEditorView({ share, path, mode }: { share: string; path: string; mode: "edit" | "view" }) {
  const [opened, setOpened] = useState<OfficeOpened | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [nonce, setNonce] = useState(0);
  const name = path.split("/").pop() ?? path;

  const load = useCallback(async () => {
    setOpened(null);
    setError(null);
    try {
      setOpened(await openDocument(share, path, mode));
    } catch (err) {
      setError(errorMessage(err));
    }
  }, [share, path, mode]);

  useEffect(() => {
    void load();
  }, [load, nonce]);

  return (
    <div className="app-frame office-frame">
      <div className="app-frame__bar">
        <span className="small muted app-frame__name">{name}</span>
        {opened && <Badge tone={opened.mode === "edit" ? "accent" : "neutral"}>{opened.mode === "edit" ? "Editing" : "Read only"}</Badge>}
        {opened?.viewReason && <span className="small muted office-frame__why">{opened.viewReason}</span>}
        <span className="app-card__spacer" />
        <Button size="sm" variant="ghost" onClick={() => setNonce((n) => n + 1)} aria-label={`Reopen ${name}`} title="Reopen">
          <RefreshIcon size={14} />
        </Button>
      </div>
      <div className="app-frame__body">
        {error ? (
          <div className="pad">
            <Alert
              tone="bad"
              title={`Couldn't open ${name}`}
              action={
                <Button size="sm" onClick={() => setNonce((n) => n + 1)}>
                  Try again
                </Button>
              }
            >
              {error}
            </Alert>
          </div>
        ) : !opened ? (
          <Loading label={`Opening ${name}…`} />
        ) : (
          <iframe
            key={opened.url}
            className="app-frame__view"
            src={opened.url}
            title={name}
            allow="fullscreen; clipboard-read; clipboard-write"
            sandbox={OFFICE_FRAME_SANDBOX}
            referrerPolicy="no-referrer"
          />
        )}
      </div>
    </div>
  );
}
