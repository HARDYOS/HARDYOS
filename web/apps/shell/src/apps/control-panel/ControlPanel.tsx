import { useState } from "react";
import { initials } from "../../format";
import { CalendarIcon, CpuIcon, DomainIcon, GpuIcon, FolderIcon, GridIcon, LayersIcon, NetworkIcon, RefreshIcon, ShareIcon, ShieldIcon, UsersIcon } from "../../icons";
import { type AppProps, useShell } from "../../shell";
import { AppLayout, PageHeader, SideNav } from "../../ui";
import { AuditLog } from "../shared";
import { Backup } from "./Backup";
import { DateTime } from "./DateTime";
import { Domain } from "./Domain";
import { FileServices } from "./FileServices";
import { DevicesView } from "../vms/devices";
import { Hardware } from "./Hardware";
import { Network } from "./Network";
import { SharedFolders } from "./SharedFolders";
import { TerminalSwitch } from "./TerminalSwitch";
import { Overview } from "./Overview";
import { Updates } from "./Updates";
import { Users } from "./Users";

const SECTIONS = [
  { id: "overview", label: "Overview", icon: <GridIcon size={16} /> },
  { id: "users", label: "Users & Groups", icon: <UsersIcon size={16} /> },
  { id: "domain", label: "Domain", icon: <DomainIcon size={16} /> },
  { id: "shares", label: "Shared Folders", icon: <FolderIcon size={16} /> },
  { id: "files", label: "File Services", icon: <ShareIcon size={16} /> },
  { id: "network", label: "Network", icon: <NetworkIcon size={16} /> },
  { id: "time", label: "Date & Time", icon: <CalendarIcon size={16} /> },
  { id: "hardware", label: "Hardware", icon: <CpuIcon size={16} /> },
  { id: "devices", label: "Devices & GPUs", icon: <GpuIcon size={16} /> },
  { id: "updates", label: "Updates", icon: <RefreshIcon size={16} /> },
  { id: "backup", label: "Backup & Restore", icon: <LayersIcon size={16} /> },
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
      {section === "domain" && <Domain />}
      {section === "shares" && <SharedFolders admin={user.role === "admin"} />}
      {section === "files" && <FileServices admin={user.role === "admin"} />}
      {section === "network" && <Network />}
      {section === "time" && <DateTime />}
      {section === "hardware" && <Hardware />}
      {section === "devices" && <DevicesView />}
      {section === "updates" && <Updates />}
      {section === "backup" && <Backup />}
      {section === "security" && (
        <>
          <PageHeader title="Security" subtitle="Who can do what, and every sign-in and change to the system, newest first." />
          <TerminalSwitch />
          <AuditLog />
        </>
      )}
    </AppLayout>
  );
}
