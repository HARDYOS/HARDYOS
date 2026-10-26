import { useState } from "react";
import { initials } from "../../format";
import { CalendarIcon, CpuIcon, GridIcon, NetworkIcon, RefreshIcon, ShieldIcon, UsersIcon } from "../../icons";
import { type AppProps, useShell } from "../../shell";
import { AppLayout, PageHeader, SideNav } from "../../ui";
import { AuditLog } from "../shared";
import { DateTime } from "./DateTime";
import { Hardware } from "./Hardware";
import { Network } from "./Network";
import { Overview } from "./Overview";
import { Updates } from "./Updates";
import { Users } from "./Users";

const SECTIONS = [
  { id: "overview", label: "Overview", icon: <GridIcon size={16} /> },
  { id: "users", label: "Users & Groups", icon: <UsersIcon size={16} /> },
  { id: "network", label: "Network", icon: <NetworkIcon size={16} /> },
  { id: "time", label: "Date & Time", icon: <CalendarIcon size={16} /> },
  { id: "hardware", label: "Hardware", icon: <CpuIcon size={16} /> },
  { id: "updates", label: "Updates", icon: <RefreshIcon size={16} /> },
  { id: "security", label: "Security", icon: <ShieldIcon size={16} /> },
];

export default function ControlPanel({ args }: AppProps) {
  const { user } = useShell();
  const [section, setSection] = useState(args?.section ?? "overview");
  const name = user.displayName || user.username;

  return (
    <AppLayout
      nav={
        <SideNav
          label="Control Panel sections"
          items={SECTIONS}
          active={section}
          onSelect={setSection}
          footer={
            <div className="row" style={{ padding: 10, borderRadius: 10, background: "var(--hos-surface)" }}>
              <span className="avatar">{initials(name)}</span>
              <div style={{ display: "flex", flexDirection: "column", minWidth: 0 }}>
                <strong className="small">{name}</strong>
                <span className="small muted">{user.role === "admin" ? "Administrator" : "User"}</span>
              </div>
            </div>
          }
        />
      }
    >
      {section === "overview" && <Overview onNavigate={setSection} />}
      {section === "users" && <Users />}
      {section === "network" && <Network />}
      {section === "time" && <DateTime />}
      {section === "hardware" && <Hardware />}
      {section === "updates" && <Updates />}
      {section === "security" && (
        <>
          <PageHeader title="Security" subtitle="Every sign-in and every change to the system, newest first." />
          <AuditLog />
        </>
      )}
    </AppLayout>
  );
}
