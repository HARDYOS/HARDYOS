import type RFBType from "@novnc/novnc";
import { useCallback, useEffect, useRef, useState } from "react";
import { api, errorMessage, unwrap } from "../../api";
import { ClipboardIcon, ExpandIcon, KeyboardIcon, MuteIcon, RefreshIcon, SpeakerIcon } from "../../icons";
import type { AppProps } from "../../shell";
import { Button, Spinner, TextInput } from "../../ui";
import { Dialog } from "../../ui/Dialog";
import { AudioPlayer, withQemuAudio } from "./qemuAudio";
import "./vms.css";

/** Keyboard Lock (Chromium): Esc, Alt+Tab and the Windows key go to the VM in full screen. */
type KeyboardLock = { lock?: (keys?: string[]) => Promise<void>; unlock?: () => void };
const keyboardLock = (): KeyboardLock | undefined => (navigator as unknown as { keyboard?: KeyboardLock }).keyboard;

type ConsoleRFB = RFBType & { setAudio: (on: boolean) => boolean; audioAcked: boolean; onAudio: ((e: { kind: string; data?: Uint8Array }) => void) | null };

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
  const rfb = useRef<ConsoleRFB | null>(null);
  const player = useRef<AudioPlayer | null>(null);
  const [status, setStatus] = useState<Status>({ kind: "connecting" });
  const [attempt, setAttempt] = useState(0);
  const [typing, setTyping] = useState(false);
  const [clip, setClip] = useState(false);
  const [remoteClip, setRemoteClip] = useState("");
  const [scale, setScale] = useState(true);
  const [sound, setSound] = useState(false);
  const [canSound, setCanSound] = useState(false);
  const [full, setFull] = useState(false);

  const connect = useCallback(async (signal: { cancelled: boolean }) => {
    setStatus({ kind: "connecting" });
    try {
      const sess = await unwrap(api.POST("/vms/{id}/console", { params: { path: { id } } }));
      const { default: RFB } = await import("@novnc/novnc");
      if (signal.cancelled || !screen.current) return;
      const AudioRFB = withQemuAudio(RFB as unknown as new (...a: unknown[]) => object);
      const r = new AudioRFB(screen.current, consoleURL(sess.path), { wsProtocols: ["binary"] }) as unknown as ConsoleRFB;
      r.scaleViewport = true;
      r.resizeSession = false;
      r.focusOnClick = true;
      r.background = "#000";
      r.onAudio = (ev) => {
        if (ev.kind === "data" && ev.data) player.current?.play(ev.data);
      };
      r.addEventListener("connect", () => {
        setStatus({ kind: "connected" });
        // QEMU acknowledges the audio extension right after the encodings.
        setTimeout(() => setCanSound(!!rfb.current?.audioAcked), 1500);
      });
      r.addEventListener("clipboard", (e) => setRemoteClip((e as CustomEvent<{ text: string }>).detail?.text ?? ""));
      r.addEventListener("disconnect", (e) => {
        const clean = (e as CustomEvent<{ clean: boolean }>).detail?.clean;
        setStatus({ kind: "closed", reason: clean ? "The screen was closed." : "The connection to the VM's screen was lost (did it stop?)." });
        rfb.current = null;
        player.current?.stop();
        player.current = null;
        setSound(false);
        setCanSound(false);
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
      player.current?.stop();
      player.current = null;
    };
  }, [connect, attempt]);

  useEffect(() => {
    const onChange = () => {
      const on = document.fullscreenElement != null && document.fullscreenElement === screen.current?.parentElement;
      setFull(on);
      if (on) void keyboardLock()?.lock?.().catch(() => undefined);
      else keyboardLock()?.unlock?.();
    };
    document.addEventListener("fullscreenchange", onChange);
    return () => document.removeEventListener("fullscreenchange", onChange);
  }, []);

  const toggleSound = () => {
    const r = rfb.current;
    if (!r) return;
    if (sound) {
      r.setAudio(false);
      player.current?.stop();
      player.current = null;
      setSound(false);
      return;
    }
    // The AudioContext has to start from the click.
    const p = new AudioPlayer();
    p.start();
    player.current = p;
    if (r.setAudio(true)) setSound(true);
  };

  const toggleFull = () => {
    if (document.fullscreenElement) void document.exitFullscreen?.();
    else void screen.current?.parentElement?.requestFullscreen?.();
  };

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
          <KeyboardIcon size={14} /> Type text…
        </Button>
        <Button size="sm" variant="ghost" disabled={status.kind !== "connected"} onClick={() => setClip(true)}>
          <ClipboardIcon size={14} /> Clipboard
        </Button>
        <Button size="sm" variant="ghost" aria-pressed={scale} onClick={() => setScale(!scale)}>
          {scale ? "Actual size" : "Fit to window"}
        </Button>
        <span className="grow" />
        <Button
          size="sm"
          variant="ghost"
          aria-pressed={sound}
          disabled={status.kind !== "connected" || !canSound}
          title={canSound ? undefined : "The VM has no sound card (turn on Sound in Hardware)"}
          onClick={toggleSound}
        >
          {sound ? <SpeakerIcon size={14} /> : <MuteIcon size={14} />} {sound ? "Sound on" : "Sound off"}
        </Button>
        <Button size="sm" variant="ghost" aria-pressed={full} onClick={toggleFull}>
          <ExpandIcon size={14} /> {full ? "Leave full screen" : "Full screen"}
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
      {clip && (
        <ClipboardDialog
          remote={remoteClip}
          onClose={() => setClip(false)}
          onSend={(text) => send((r) => r.clipboardPasteFrom(text))}
        />
      )}
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

/** Copy and paste with the VM (qemu-vdagent: the guest needs spice-vdagent). */
export function ClipboardDialog({ remote, onClose, onSend }: { remote: string; onClose: () => void; onSend: (t: string) => void }) {
  const [text, setText] = useState("");
  const [copied, setCopied] = useState(false);
  return (
    <Dialog
      title="Clipboard"
      description="Copy and paste between your computer and the VM. It needs the clipboard turned on in the VM's Hardware and spice-vdagent (or the VirtIO guest tools) running in it; otherwise use Type text."
      onClose={onClose}
      onSubmit={() => {
        onSend(text);
        onClose();
      }}
      footer={
        <>
          <Button onClick={onClose}>Close</Button>
          <Button type="submit" variant="primary" disabled={!text}>
            Paste into the VM
          </Button>
        </>
      }
    >
      <div className="stack">
        <label className="stack" style={{ gap: 4 }}>
          <span className="small muted">Copied in the VM</span>
          <textarea className="input mono" rows={3} readOnly value={remote} aria-label="Copied in the VM" placeholder="Nothing yet" />
        </label>
        <div>
          <Button
            size="sm"
            disabled={!remote}
            onClick={async () => {
              try {
                await navigator.clipboard.writeText(remote);
                setCopied(true);
              } catch {
                setCopied(false);
              }
            }}
          >
            {copied ? "Copied" : "Copy to my computer"}
          </Button>
        </div>
        <label className="stack" style={{ gap: 4 }}>
          <span className="small muted">To paste into the VM</span>
          <textarea className="input mono" rows={3} value={text} aria-label="To paste into the VM" onChange={(e) => setText(e.target.value)} spellCheck={false} />
        </label>
      </div>
    </Dialog>
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
