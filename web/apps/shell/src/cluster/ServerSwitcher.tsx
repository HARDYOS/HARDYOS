import type { User } from "@hardy/api-client";
import { useEffect, useRef, useState } from "react";
import { NetworkIcon } from "../icons";
import { Dot } from "../ui";
import { openApp } from "../wm/open";
import { useClusterNodes, useClusterScope } from "./scope";

/**
 * The menu bar's server switcher: shown only in a cluster. It lists the
 * servers with a health dot and picks the one new windows open for; the
 * last item opens the Cluster app's overview.
 */
export function ServerSwitcher({ user }: { user: User }) {
  const { data } = useClusterNodes();
  const { node, setNode } = useClusterScope();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const onDown = (e: PointerEvent) => !ref.current?.contains(e.target as Node) && setOpen(false);
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    document.addEventListener("pointerdown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("pointerdown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);
  if (!data?.member) return null;
  const self = data.nodes.find((n) => n.self);
  const current = data.nodes.find((n) => n.id === node) ?? self;
  return (
    <div className="popover-anchor" ref={ref}>
      <button
        type="button"
        className="menubar__switcher"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label={`Server: ${current?.name ?? "this server"}`}
        onClick={() => setOpen(!open)}
      >
        <NetworkIcon size={14} />
        <span>{current?.name ?? "this server"}</span>
        <Dot tone={!data.quorate ? "warn" : current?.healthy ? "good" : "bad"} />
      </button>
      {open && (
        <div className="popover popover--menu glass" role="menu" aria-label="Servers">
          <div className="popover__head">{data.name || "Cluster"}</div>
          {data.nodes.map((n) => (
            <button
              key={n.id}
              type="button"
              role="menuitemradio"
              aria-checked={(node || self?.id) === n.id}
              className="menu-item"
              onClick={() => {
                setNode(n.self ? "" : n.id);
                setOpen(false);
              }}
            >
              <Dot tone={n.healthy ? "good" : "bad"} />
              <span>{n.name}</span>
              <span className="muted small">
                {n.role}
                {n.self ? " · this server" : ""}
                {n.leader ? " · leader" : ""}
              </span>
            </button>
          ))}
          {user.role === "admin" && (
            <div className="popover__foot">
              <button
                type="button"
                onClick={() => {
                  setOpen(false);
                  openApp("os.hardy.cluster", user, { section: "overview" });
                }}
              >
                Cluster overview
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
