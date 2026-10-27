import type RFBType from "@novnc/novnc";
import { useCallback, useEffect, useRef, useState } from "react";
import { api, errorMessage, unwrap } from "../../api";
import { ClipboardIcon, ExpandIcon, KeyboardIcon, RefreshIcon } from "../../icons";
import type { AppProps } from "../../shell";
import { Button, Spinner, TextInput } from "../../ui";
import { Dialog } from "../../ui/Dialog";
import "./vms.css";

type Status = { kind: "connecting" } | { kind: "connected" } | { kind: "closed"; reason: string };

/** The WebSocket address for a console path from hardyd. */
export function consoleURL(path: string, loc: Pick<Location, "protocol" | "host"> = window.location): string {
  const scheme = loc.protocol === "https:" ? "wss:" : "ws:";
  return `${scheme}//${loc.host}${path}`;
}

/** X11 keysyms for typing text: printable Latin-1 maps to itself. */
export function keysymsFor(text: string): { keysym: number; code: string | null }[] {
  const out: { keysym: number; code: string | null }[] = [];
  for (const ch of text.replace(/\r\n/g, "\n")) {
    if (ch === "\n") out.push({ keysym: 0xff0d, code: "Enter" });
    else if (ch === "\t") out.push({ keysym: 0xff09, code: "Tab" });
    else {
      const cp = ch.codePointAt(0)!;
      if (cp >= 0x20 && cp <= 0xff) out.push({ keysym: cp, code: null });
      else if (cp > 0xff) out.push({ keysym: 0x01000000 + cp, code: null });
    }
  }
  return out;
}

/** A VM's screen in a desktop window (noVNC over hardyd's console relay). */
export default function VMConsole({ args }: AppProps) {
  const id = args?.id ?? "";
  return <ConsoleView id={id} name={args?.title ?? id} />;
}

export function ConsoleView({ id, name }: { id: string; name: string }) {
  const screen = useRef<HTMLDivElement>(null);
  const rfb = useRef<RFBType | null>(null);
  const [status, setStatus] = useState<Status>({ kind: "connecting" });
  const [attempt, setAttempt] = useState(0);
  const [typing, setTyping] = useState(false);
  const [scale, setScale] = useState(true);

  const connect = useCallback(async (signal: { cancelled: boolean }) => {
    setStatus({ kind: "connecting" });
    try {
      const sess = await unwrap(api.POST("/vms/{id}/console", { params: { path: { id } } }));
      const { default: RFB } = await import("@novnc/novnc");
      if (signal.cancelled || !screen.current) return;
      const r = new RFB(screen.current, consoleURL(sess.path), { wsProtocols: ["binary"] });
      r.scaleViewport = true;
      r.resizeSession = false;
      r.focusOnClick = true;
      r.background = "#000";
      r.addEventListener("connect", () => setStatus({ kind: "connected" }));
      r.addEventListener("disconnect", (e) => {
        const clean = (e as CustomEvent<{ clean: boolean }>).detail?.clean;
        setStatus({ kind: "closed", reason: clean ? "The screen was closed." : "The connection to the VM's screen was lost (did it stop?)." });
        rfb.current = null;
      });
      rfb.current = r;
    } catch (e) {
      if (!signal.cancelled) setStatus({ kind: "closed", reason: errorMessage(e) });
    }
  }, [id]);

  useEffect(() => {
    const signal = { cancelled: false };
    void connect(signal);
    return () => {
      signal.cancelled = true;
      rfb.current?.disconnect();
      rfb.current = null;
    };
  }, [connect, attempt]);

  useEffect(() => {
    if (rfb.current) rfb.current.scaleViewport = scale;
  }, [scale]);

  const send = (fn: (r: RFBType) => void) => {
    if (rfb.current) {
      fn(rfb.current);
      rfb.current.focus();
    }
  };

  return (
    <div className="vmc">
      <div className="vmc__bar" role="toolbar" aria-label={`${name} screen`}>
        <Button size="sm" variant="ghost" disabled={status.kind !== "connected"} onClick={() => send((r) => r.sendCtrlAltDel())}>
          <KeyboardIcon size={14} /> Ctrl+Alt+Del
        </Button>
        <Button size="sm" variant="ghost" disabled={status.kind !== "connected"} onClick={() => setTyping(true)}>
          <ClipboardIcon size={14} /> Type text…
        </Button>
        <Button size="sm" variant="ghost" aria-pressed={scale} onClick={() => setScale(!scale)}>
          {scale ? "Actual size" : "Fit to window"}
        </Button>
        <span className="grow" />
        <Button size="sm" variant="ghost" onClick={() => screen.current?.parentElement?.requestFullscreen?.()}>
          <ExpandIcon size={14} /> Full screen
        </Button>
      </div>
      <div className="vmc__screen">
        <div ref={screen} data-testid="vm-screen" />
        {status.kind !== "connected" && (
          <div className="vmc__overlay">
            {status.kind === "connecting" ? (
              <div className="row" style={{ gap: 10 }}>
                <Spinner /> Connecting to {name}…
              </div>
            ) : (
              <div className="stack" style={{ alignItems: "center", gap: 12 }}>
                <div>{status.reason}</div>
                <Button onClick={() => setAttempt((n) => n + 1)}>
                  <RefreshIcon size={14} /> Connect again
                </Button>
              </div>
            )}
          </div>
        )}
      </div>
      {typing && (
        <TypeDialog
          onClose={() => setTyping(false)}
          onType={(text) =>
            send((r) => {
              for (const k of keysymsFor(text)) {
                r.sendKey(k.keysym, k.code, true);
                r.sendKey(k.keysym, k.code, false);
              }
            })
          }
        />
      )}
    </div>
  );
}

function TypeDialog({ onClose, onType }: { onClose: () => void; onType: (t: string) => void }) {
  const [text, setText] = useState("");
  return (
    <Dialog
      title="Type text into the VM"
      description="HardyOS types it for you, key by key: handy for passwords and commands. Paste it here first."
      onClose={onClose}
      onSubmit={() => {
        onType(text);
        onClose();
      }}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" disabled={!text}>
            Type it
          </Button>
        </>
      }
    >
      <TextInput aria-label="Text to type" value={text} onChange={(e) => setText(e.target.value)} autoComplete="off" spellCheck={false} />
    </Dialog>
  );
}
