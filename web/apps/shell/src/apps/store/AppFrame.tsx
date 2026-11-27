import type { AppOpen } from "@hardy/api-client";
import { useCallback, useEffect, useState } from "react";
import { errorMessage, unwrap } from "../../api";
import { nodeApi } from "../../cluster/scope";
import { ExternalIcon, RefreshIcon } from "../../icons";
import { APP_WINDOW, type AppProps } from "../../shell";
import { Alert, Button, Loading } from "../../ui";
import { toast } from "../../ui/toasts";

/** The window id for an installed app. */
export const appWindowId = (id: string) => `${APP_WINDOW}:${id}`;

/**
 * Asks hardyd where to open an app: a fresh single-use proxy URL each time.
 * node is the server the window is for ("" or undefined: this one); a
 * cluster app opens wherever it runs, and an app on another server through
 * this server's window proxy and the cluster relay.
 */
export async function openUrl(id: string, node?: string): Promise<AppOpen> {
  return unwrap(nodeApi(node).POST("/apps/{id}/open", { params: { path: { id } } }));
}

/**
 * Opens an app in a new browser tab. The tab is opened before asking the
 * server, so popup blockers see it as the click's own window.
 */
export async function openInNewTab(id: string, name: string, node?: string) {
  const w = window.open("about:blank", "_blank");
  try {
    const r = await openUrl(id, node);
    if (w) {
      w.opener = null;
      w.location.href = r.url;
    } else {
      window.open(r.url, "_blank", "noopener");
    }
  } catch (err) {
    w?.close();
    toast("error", `Couldn't open ${name}`, errorMessage(err));
  }
}

/**
 * What an app in a desktop window may do. No allow-top-navigation: an app
 * can't send the desktop's tab somewhere else. allow-same-origin is the
 * app's own origin (its proxy port), never the desktop's.
 */
export const APP_FRAME_SANDBOX =
  "allow-scripts allow-same-origin allow-forms allow-popups allow-popups-to-escape-sandbox allow-modals allow-downloads";

/** Whether a URL can be shown inside the desktop (no mixed content). */
export function frameable(o: AppOpen, desktopProtocol = window.location.protocol): boolean {
  return o.proxied || !(desktopProtocol === "https:" && o.url.startsWith("http:"));
}

/** An installed app's web page in a desktop window. */
export default function AppFrame({ args }: AppProps) {
  const id = args?.id ?? "";
  const name = args?.title ?? id;
  return <AppFrameView id={id} name={name} node={args?.node} />;
}

/** An app's window; node is the server it runs on ("" or undefined: this one). */
export function AppFrameView({ id, name, node }: { id: string; name: string; node?: string }) {
  const [open, setOpen] = useState<AppOpen | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [nonce, setNonce] = useState(0);

  const load = useCallback(async () => {
    setError(null);
    setOpen(null);
    try {
      setOpen(await openUrl(id, node));
    } catch (err) {
      setError(errorMessage(err));
    }
  }, [id, node]);

  useEffect(() => {
    void load();
  }, [load, nonce]);

  return (
    <div className="app-frame">
      <div className="app-frame__bar">
        <span className="small muted app-frame__name">{name}</span>
        {open?.published && <span className="small mono muted">{new URL(open.url).host}</span>}
        <span className="app-card__spacer" />
        <Button size="sm" variant="ghost" onClick={() => setNonce((n) => n + 1)} aria-label={`Reload ${name}`} title="Reload">
          <RefreshIcon size={14} />
        </Button>
        <Button size="sm" variant="ghost" onClick={() => openInNewTab(id, name, node)}>
          <ExternalIcon size={14} /> Open in new tab
        </Button>
      </div>
      <div className="app-frame__body">
        {error ? (
          <div className="pad">
            <Alert tone="bad" title={`Couldn't open ${name}`} action={<Button size="sm" onClick={() => setNonce((n) => n + 1)}>Try again</Button>}>
              {error}
            </Alert>
          </div>
        ) : !open ? (
          <Loading label={`Opening ${name}…`} />
        ) : frameable(open) ? (
          <iframe
            key={open.url}
            className="app-frame__view"
            src={open.url}
            title={name}
            allow="fullscreen; clipboard-read; clipboard-write; autoplay; picture-in-picture"
            sandbox={APP_FRAME_SANDBOX}
            referrerPolicy="no-referrer"
          />
        ) : (
          <div className="pad">
            <Alert tone="info" title={`${name} opens in its own tab`} action={<Button size="sm" variant="primary" onClick={() => openInNewTab(id, name, node)}>Open in new tab</Button>}>
              The window proxy isn't running, and the desktop can't show an http:// page inside its secure window.
            </Alert>
          </div>
        )}
      </div>
    </div>
  );
}
