import { type PointerEvent as ReactPointerEvent, type ReactNode, useCallback, useRef } from "react";
import { DOCK_RESERVE, MENUBAR_H, MIN_H, MIN_W, type Win, useWM } from "./store";

type Edge = "n" | "s" | "e" | "w" | "ne" | "nw" | "se" | "sw";
const EDGES: Edge[] = ["n", "s", "e", "w", "ne", "nw", "se", "sw"];

interface Props {
  win: Win;
  focused: boolean;
  children: ReactNode;
}

/** A desktop window: drag by the title bar, resize from any edge, double-click to maximize. */
export function Window({ win, focused, children }: Props) {
  const { focus, close, minimize, toggleMaximize, move, resize } = useWM.getState();
  const drag = useRef<{ dx: number; dy: number } | null>(null);
  const sizing = useRef<{ edge: Edge; sx: number; sy: number; r: { x: number; y: number; w: number; h: number } } | null>(null);

  const onTitlePointerDown = useCallback(
    (e: ReactPointerEvent<HTMLDivElement>) => {
      if ((e.target as HTMLElement).closest("button") || e.button !== 0) return;
      focus(win.id);
      if (win.maximized) return;
      drag.current = { dx: e.clientX - win.x, dy: e.clientY - win.y };
      e.currentTarget.setPointerCapture(e.pointerId);
    },
    [focus, win.id, win.maximized, win.x, win.y],
  );

  const onTitlePointerMove = (e: ReactPointerEvent<HTMLDivElement>) => {
    if (!drag.current) return;
    move(win.id, e.clientX - drag.current.dx, e.clientY - drag.current.dy);
  };

  const endDrag = (e: ReactPointerEvent<HTMLElement>) => {
    drag.current = null;
    sizing.current = null;
    if (e.currentTarget.hasPointerCapture(e.pointerId)) e.currentTarget.releasePointerCapture(e.pointerId);
  };

  const onEdgeDown = (edge: Edge) => (e: ReactPointerEvent<HTMLDivElement>) => {
    if (e.button !== 0 || win.maximized) return;
    e.stopPropagation();
    focus(win.id);
    sizing.current = { edge, sx: e.clientX, sy: e.clientY, r: { x: win.x, y: win.y, w: win.w, h: win.h } };
    e.currentTarget.setPointerCapture(e.pointerId);
  };

  const onEdgeMove = (e: ReactPointerEvent<HTMLDivElement>) => {
    const s = sizing.current;
    if (!s) return;
    const dx = e.clientX - s.sx;
    const dy = e.clientY - s.sy;
    let { x, y, w, h } = s.r;
    if (s.edge.includes("e")) w = Math.max(MIN_W, s.r.w + dx);
    if (s.edge.includes("s")) h = Math.max(MIN_H, s.r.h + dy);
    if (s.edge.includes("w")) {
      w = Math.max(MIN_W, s.r.w - dx);
      x = s.r.x + (s.r.w - w);
    }
    if (s.edge.includes("n")) {
      h = Math.max(MIN_H, s.r.h - dy);
      y = s.r.y + (s.r.h - h);
    }
    resize(win.id, { x, y, w, h });
  };

  const style = win.maximized
    ? { left: 8, top: MENUBAR_H + 8, right: 8, bottom: DOCK_RESERVE, zIndex: win.z }
    : { left: win.x, top: win.y, width: win.w, height: win.h, zIndex: win.z };

  return (
    <section
      className={`window glass ${focused ? "is-focused" : ""} ${win.maximized ? "is-maximized" : ""}`}
      style={{ ...style, display: win.minimized ? "none" : undefined }}
      aria-label={`${win.title} window`}
      onPointerDownCapture={() => focus(win.id)}
    >
      <div
        className="window__titlebar"
        onPointerDown={onTitlePointerDown}
        onPointerMove={onTitlePointerMove}
        onPointerUp={endDrag}
        onPointerCancel={endDrag}
        onDoubleClick={(e) => !(e.target as HTMLElement).closest("button") && toggleMaximize(win.id)}
      >
        <div className="traffic-lights">
          <button type="button" className="traffic traffic--close" aria-label={`Close ${win.title}`} onClick={() => close(win.id)} />
          <button type="button" className="traffic traffic--min" aria-label={`Minimize ${win.title}`} onClick={() => minimize(win.id)} />
          <button
            type="button"
            className="traffic traffic--max"
            aria-label={win.maximized ? `Restore ${win.title}` : `Maximize ${win.title}`}
            onClick={() => toggleMaximize(win.id)}
          />
        </div>
        <div className="window__title">{win.title}</div>
      </div>
      <div className="window__body">{children}</div>
      {!win.maximized &&
        EDGES.map((edge) => (
          <div
            key={edge}
            className={`window__edge window__edge--${edge}`}
            onPointerDown={onEdgeDown(edge)}
            onPointerMove={onEdgeMove}
            onPointerUp={endDrag}
            onPointerCancel={endDrag}
            aria-hidden="true"
          />
        ))}
    </section>
  );
}
