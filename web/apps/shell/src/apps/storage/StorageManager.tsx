import { useState } from "react";
import { useDataPools } from "../../hooks/queries";
import { ActivityIcon, CalendarIcon, CameraIcon, DiskIcon, GridIcon, LayersIcon, PlusIcon } from "../../icons";
import type { AppProps } from "../../shell";
import { AppLayout, Dot, type NavItem, SideNav } from "../../ui";
import { CreatePool } from "./CreatePool";
import { Datasets } from "./Datasets";
import { Disks } from "./Disks";
import { Health } from "./Health";
import { PoolsOverview } from "./PoolsOverview";
import { PoolDetail } from "./PoolDetail";
import { Schedules } from "./Schedules";
import { Snapshots } from "./Snapshots";

export function healthTone(h: string) {
  return h === "ONLINE" ? "good" : h === "DEGRADED" ? "warn" : "bad";
}

export default function StorageManager({ args }: AppProps) {
  const pools = useDataPools();
  const [section, setSection] = useState(args?.pool ? `pool:${args.pool}` : (args?.section ?? "overview"));

  const items: NavItem[] = [
    { id: "overview", label: "Overview", icon: <GridIcon size={16} /> },
    ...(pools.data ?? []).map((p) => ({
      id: `pool:${p.name}`,
      label: p.name,
      group: "Pools",
      icon: <Dot tone={healthTone(p.health)} />,
    })),
    { id: "create", label: "Create pool", group: "Pools", icon: <PlusIcon size={16} /> },
    { id: "health", label: "Health", group: "Manage", icon: <ActivityIcon size={16} /> },
    { id: "disks", label: "Disks", group: "Manage", icon: <DiskIcon size={16} /> },
    { id: "datasets", label: "Datasets", group: "Manage", icon: <LayersIcon size={16} /> },
    { id: "snapshots", label: "Snapshots", group: "Manage", icon: <CameraIcon size={16} /> },
    { id: "schedules", label: "Schedules", group: "Manage", icon: <CalendarIcon size={16} /> },
  ];

  const poolName = section.startsWith("pool:") ? section.slice(5) : null;

  return (
    <AppLayout nav={<SideNav label="Storage sections" items={items} active={section} onSelect={setSection} />}>
      {section === "overview" && <PoolsOverview onOpenPool={(p) => setSection(`pool:${p}`)} onCreate={() => setSection("create")} />}
      {poolName && <PoolDetail key={poolName} pool={poolName} onGone={() => setSection("overview")} />}
      {section === "create" && <CreatePool onCreated={(p) => setSection(`pool:${p}`)} />}
      {section === "health" && <Health />}
      {section === "disks" && <Disks initial={args?.disk} />}
      {section === "datasets" && <Datasets />}
      {section === "snapshots" && <Snapshots />}
      {section === "schedules" && <Schedules />}
    </AppLayout>
  );
}
