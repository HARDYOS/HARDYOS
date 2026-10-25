import type { CSSProperties, ReactNode } from "react";

export interface WindowProps {
  title: string;
  children: ReactNode;
  style?: CSSProperties;
  onClose?: () => void;
}

/**
 * A desktop window frame. Phase 0 renders a static window; the window manager
 * (drag, resize, snap, focus order, minimize) arrives with Phase 1 PR 4.
 */
export function Window({ title, children, style, onClose }: WindowProps) {
  return (
    <section className="window glass" style={style} aria-label={`${title} window`}>
      <div className="window__titlebar">
        <button className="traffic traffic--close" aria-label="Close window" onClick={onClose} />
        <button className="traffic traffic--min" aria-label="Minimize window" />
        <button className="traffic traffic--max" aria-label="Maximize window" />
        <div className="window__title">{title}</div>
      </div>
      <div className="window__body">{children}</div>
    </section>
  );
}
