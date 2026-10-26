import "@xterm/xterm/css/xterm.css";
import { FitAddon } from "@xterm/addon-fit";
import { Terminal as XTerm } from "@xterm/xterm";
import { useEffect, useRef, useState } from "react";
import { ApiFailure, api, errorMessage, unwrap } from "../../api";
import { LockIcon, TerminalIcon } from "../../icons";
import type { AppProps } from "../../shell";
import { Alert, Button, Field, TextInput } from "../../ui";

type Phase = { kind: "locked" } | { kind: "open"; ticket: string } | { kind: "closed"; reason: string };

/** A root shell on the server, after re-entering your password. */
export default function TerminalApp(_: AppProps) {
  const [phase, setPhase] = useState<Phase>({ kind: "locked" });
  if (phase.kind === "open") return <Session ticket={phase.ticket} onClosed={(reason) => setPhase({ kind: "closed", reason })} />;
  return <Unlock closed={phase.kind === "closed" ? phase.reason : undefined} onTicket={(ticket) => setPhase({ kind: "open", ticket })} />;
}

function Unlock({ closed, onTicket }: { closed?: string; onTicket: (t: string) => void }) {
  const [pw, setPw] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      const r = await unwrap(api.POST("/terminal/session", { body: { password: pw } }));
      setPw("");
      onTicket(r.ticket);
    } catch (err) {
      setError(err);
      setBusy(false);
    }
  };
  const disabled = error instanceof ApiFailure && error.code === "disabled";
  return (
    <div className="pad center-fill">
      <form
        className="stack terminal-unlock"
        onSubmit={(e) => {
          e.preventDefault();
          if (pw) void submit();
        }}
      >
        <span className="app-tile" style={{ background: "#0F172A", alignSelf: "center" }}>
          <TerminalIcon size={30} />
        </span>
        <h2 style={{ margin: 0, textAlign: "center" }}>Terminal</h2>
        <p className="small muted" style={{ margin: 0, textAlign: "center" }}>
          A root shell on this server: anything typed here runs with full control of HardyOS and your data. Enter your password to
          open it. It closes after 15 minutes without typing, and every session is recorded in the security log.
        </p>
        {closed && <Alert tone="info">{closed}</Alert>}
        {error != null && <Alert tone={disabled ? "warn" : "bad"}>{errorMessage(error)}</Alert>}
        <Field label="Your password">
          {(id) => <TextInput id={id} type="password" autoComplete="current-password" autoFocus value={pw} onChange={(e) => setPw(e.target.value)} />}
        </Field>
        <Button type="submit" variant="primary" busy={busy} disabled={!pw}>
          <LockIcon size={15} /> Open terminal
        </Button>
      </form>
    </div>
  );
}

const theme = {
  background: "#05070d",
  foreground: "#eef1f7",
  cursor: "#22d3ee",
  cursorAccent: "#05070d",
  selectionBackground: "rgba(34, 211, 238, 0.3)",
  black: "#1b2030",
  brightBlack: "#5b6478",
  red: "#f87171",
  brightRed: "#fca5a5",
  green: "#34d399",
  brightGreen: "#6ee7b7",
  yellow: "#fbbf24",
  brightYellow: "#fcd34d",
  blue: "#60a5fa",
  brightBlue: "#93c5fd",
  magenta: "#a78bfa",
  brightMagenta: "#c4b5fd",
  cyan: "#22d3ee",
  brightCyan: "#67e8f9",
  white: "#c7cdd9",
  brightWhite: "#ffffff",
};

function Session({ ticket, onClosed }: { ticket: string; onClosed: (reason: string) => void }) {
  const host = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const el = host.current;
    if (!el) return;
    const term = new XTerm({
      theme,
      fontFamily: '"JetBrains Mono", ui-monospace, monospace',
      fontSize: 13,
      cursorBlink: true,
      scrollback: 5000,
      allowProposedApi: false,
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(el);
    fit.fit();

    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    const ws = new WebSocket(`${proto}//${window.location.host}/api/v1/terminal/ws?ticket=${encodeURIComponent(ticket)}&cols=${term.cols}&rows=${term.rows}`);
    ws.binaryType = "arraybuffer";
    let reason = "The terminal closed.";
    const enc = new TextEncoder();
    ws.onmessage = (e) => {
      if (typeof e.data === "string") {
        try {
          const m = JSON.parse(e.data) as { type: string; reason?: string };
          if (m.type === "closed" && m.reason) reason = m.reason;
        } catch {
          // ignore
        }
        return;
      }
      term.write(new Uint8Array(e.data as ArrayBuffer));
    };
    ws.onclose = (e) => {
      if (e.reason && e.reason !== "the browser closed it") reason = /shell ended/.test(e.reason) ? "The shell ended." : reason;
      onClosed(reason);
    };
    const input = term.onData((d) => ws.readyState === WebSocket.OPEN && ws.send(enc.encode(d)));
    const binary = term.onBinary((d) => {
      if (ws.readyState !== WebSocket.OPEN) return;
      const b = new Uint8Array(d.length);
      for (let i = 0; i < d.length; i++) b[i] = d.charCodeAt(i) & 255;
      ws.send(b);
    });
    const resized = term.onResize(({ cols, rows }) => ws.readyState === WebSocket.OPEN && ws.send(JSON.stringify({ type: "resize", cols, rows })));
    const ro = new ResizeObserver(() => {
      try {
        fit.fit();
      } catch {
        // window minimized
      }
    });
    ro.observe(el);
    term.focus();
    return () => {
      ro.disconnect();
      input.dispose();
      binary.dispose();
      resized.dispose();
      ws.onclose = null;
      ws.close();
      term.dispose();
    };
    // The session lives as long as this component; onClosed is stable enough.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ticket]);
  return <div ref={host} className="terminal-host" aria-label="Terminal" />;
}
