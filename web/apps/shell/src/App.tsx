import { useState } from "react";
import { Dock, type DockApp } from "./components/Dock";
import { MenuBar } from "./components/MenuBar";
import { Window } from "./components/Window";
import { formatUptime, useSystemInfo } from "./hooks/useSystemInfo";
import {
  ActivityIcon,
  BagIcon,
  FolderIcon,
  ListIcon,
  SlidersIcon,
  StorageIcon,
  TerminalIcon,
} from "./icons";

export function App() {
  const [welcomeOpen, setWelcomeOpen] = useState(true);
  const info = useSystemInfo();

  const apps: DockApp[] = [
    { id: "files", name: "Files", color: "#2F6BFF", icon: <FolderIcon size={26} /> },
    { id: "storage", name: "Storage Manager", color: "#0E9F75", icon: <StorageIcon size={26} /> },
    {
      id: "control",
      name: "Control Panel",
      color: "#475569",
      icon: <SlidersIcon size={26} />,
      running: welcomeOpen,
      onOpen: () => setWelcomeOpen(true),
    },
    { id: "store", name: "App Store", color: "#7C5CF5", icon: <BagIcon size={26} /> },
    { id: "terminal", name: "Terminal", color: "#11151F", icon: <TerminalIcon size={26} color="#7CF2C4" /> },
    { id: "monitor", name: "Resource Monitor", color: "#E08A12", icon: <ActivityIcon size={26} /> },
    { id: "logs", name: "Log Center", color: "#D9475A", icon: <ListIcon size={26} /> },
  ];

  return (
    <div className="desktop">
      <MenuBar appName={welcomeOpen ? "Control Panel" : "HardyOS"} />

      {welcomeOpen && (
        <Window
          title="Control Panel"
          onClose={() => setWelcomeOpen(false)}
          style={{ left: "max(24px, calc(50% - 360px))", top: 72, width: 720, height: 420 }}
        >
          <h1 style={{ margin: 0, fontSize: 24, fontWeight: 700, letterSpacing: "-0.02em" }}>Welcome to HardyOS</h1>
          <p style={{ margin: "6px 0 22px", fontSize: 13, color: "var(--hos-text-muted)" }}>
            Phase 0 preview. Storage, apps and settings arrive in the next builds.
          </p>
          <SystemStatus info={info} />
        </Window>
      )}

      <Dock apps={apps} />
    </div>
  );
}

function SystemStatus({ info }: { info: ReturnType<typeof useSystemInfo> }) {
  if (info.state === "loading") {
    return <p style={{ color: "var(--hos-text-muted)" }}>Checking hardyd…</p>;
  }
  if (info.state === "error") {
    return (
      <div className="stat" role="alert">
        <span className="stat__label">Control plane</span>
        <span style={{ display: "flex", alignItems: "center", gap: 8, fontWeight: 600 }}>
          <span className="dot" style={{ background: "var(--hos-bad)" }} />
          {info.message}
        </span>
      </div>
    );
  }
  return (
    <div className="stat-grid">
      <div className="stat">
        <span className="stat__label">Control plane</span>
        <span style={{ display: "flex", alignItems: "center", gap: 8, fontWeight: 600 }}>
          <span className="dot" style={{ background: "var(--hos-good)" }} />
          Healthy
        </span>
      </div>
      <div className="stat">
        <span className="stat__label">Version</span>
        <span className="stat__value">{info.version.version}</span>
      </div>
      <div className="stat">
        <span className="stat__label">hardyd uptime</span>
        <span className="stat__value">{formatUptime(info.health.uptimeSeconds)}</span>
      </div>
    </div>
  );
}
