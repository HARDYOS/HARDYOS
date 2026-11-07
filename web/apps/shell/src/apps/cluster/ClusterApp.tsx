import { useState } from "react";
import { GlobeIcon, GridIcon, NetworkIcon, PlusIcon, ShieldIcon } from "../../icons";
import { type AppProps } from "../../shell";
import { AppLayout, Loading, PageHeader, SideNav, ErrorBox } from "../../ui";
import { useClusterStatus } from "../../cluster/scope";
import { AddServer, CreateOrJoin } from "./Join";
import { Nodes } from "./Nodes";
import { Overview } from "./Overview";
import { Witness } from "./Witness";
import "../../cluster/cluster.css";

/**
 * The Cluster app (phase 8 part A): overview (servers, quorum, leader,
 * control paths, witness), servers (leave, remove), adding a server and
 * the witness. Parts B and C add Storage, Workloads and HA sections.
 */
export default function ClusterApp({ args }: AppProps) {
  const status = useClusterStatus();
  const [section, setSection] = useState(args?.section ?? "overview");
  if (status.isLoading) return <Loading />;
  if (status.error) return <ErrorBox error={status.error} onRetry={() => status.refetch()} />;
  const st = status.data!;
  if (!st.member) {
    return (
      <div className="app-pad">
        <PageHeader title="Cluster" subtitle="Join several HardyOS servers into one: one desktop, shared storage, high availability." />
        <CreateOrJoin />
      </div>
    );
  }
  const items = [
    { id: "overview", label: "Overview", icon: <GridIcon size={16} /> },
    { id: "nodes", label: "Servers", icon: <NetworkIcon size={16} /> },
    { id: "add", label: "Add server", icon: <PlusIcon size={16} /> },
    { id: "witness", label: "Witness", icon: <ShieldIcon size={16} /> },
  ];
  return (
    <AppLayout
      nav={
        <SideNav
          label="Cluster sections"
          items={items}
          active={section}
          onSelect={setSection}
          footer={
            <div className="small muted" style={{ padding: 10 }}>
              <GlobeIcon size={12} /> {st.name}
            </div>
          }
        />
      }
    >
      {section === "overview" && <Overview st={st} />}
      {section === "nodes" && <Nodes st={st} />}
      {section === "add" && <AddServer st={st} />}
      {section === "witness" && <Witness st={st} />}
    </AppLayout>
  );
}
