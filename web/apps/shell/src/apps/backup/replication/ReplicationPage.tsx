import { useState } from "react";
import { PageHeader } from "../../../ui";
import { AcceptPanel } from "./AcceptPanel";
import { ReplicationTab } from "./ReplicationTab";

const TABS = [
  ["send", "Send to another server"],
  ["accept", "Accept from another server"],
] as const;

/**
 * Control Panel › Replication. A temporary home for the Backup app's
 * Replication tab, with the receiving side next to it.
 */
export function ReplicationPage({ initialTab = "send" }: { initialTab?: "send" | "accept" }) {
  const [tab, setTab] = useState<"send" | "accept">(initialTab);
  return (
    <>
      <PageHeader
        title="Replication"
        subtitle="Copy shared folders, apps and VMs to another HardyOS server on a schedule, over your network or NetBird. After the first copy, only changes travel."
      />
      <div className="tabs" role="tablist" aria-label="Replication sections">
        {TABS.map(([id, label]) => (
          <button key={id} type="button" role="tab" className="tabs__tab" aria-selected={tab === id} onClick={() => setTab(id)}>
            {label}
          </button>
        ))}
      </div>
      {tab === "send" ? <ReplicationTab /> : <AcceptPanel />}
    </>
  );
}
