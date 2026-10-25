import { useEffect, useState } from "react";
import { BellIcon, LogoIcon, SearchIcon } from "../icons";

const fmt = new Intl.DateTimeFormat(undefined, {
  weekday: "short",
  month: "short",
  day: "numeric",
  hour: "numeric",
  minute: "2-digit",
});

export function MenuBar({ appName }: { appName: string }) {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 15_000);
    return () => clearInterval(t);
  }, []);

  return (
    <header className="menubar glass" role="banner">
      <LogoIcon size={16} aria-label="HardyOS" aria-hidden={false} role="img" />
      <span className="menubar__app">{appName}</span>
      <span className="menubar__spacer" />
      <button aria-label="Search" style={{ background: "none", border: 0, padding: 0, display: "flex" }}>
        <SearchIcon size={16} />
      </button>
      <button aria-label="Notifications" style={{ background: "none", border: 0, padding: 0, display: "flex" }}>
        <BellIcon size={16} />
      </button>
      <time className="menubar__clock" dateTime={now.toISOString()}>
        {fmt.format(now)}
      </time>
    </header>
  );
}
