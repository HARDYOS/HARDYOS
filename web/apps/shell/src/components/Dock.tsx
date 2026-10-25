import type { ReactNode } from "react";

export interface DockApp {
  id: string;
  name: string;
  color: string;
  icon: ReactNode;
  running?: boolean;
  onOpen?: () => void;
}

export function Dock({ apps }: { apps: DockApp[] }) {
  return (
    <nav className="dock glass" aria-label="Dock">
      {apps.map((a) => (
        <button
          key={a.id}
          className="dock__item"
          aria-label={a.running ? `${a.name} (open)` : a.name}
          title={a.name}
          onClick={a.onOpen}
        >
          <span className="dock__tile" style={{ background: a.color, color: "#fff" }}>
            {a.icon}
          </span>
          <span className={a.running ? "dock__dot dock__dot--on" : "dock__dot"} />
        </button>
      ))}
    </nav>
  );
}
