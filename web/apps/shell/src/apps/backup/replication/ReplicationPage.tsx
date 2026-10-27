import { useShell } from "../../../shell";
import { Button, PageHeader } from "../../../ui";
import { AcceptPanel } from "./AcceptPanel";

/**
 * Control Panel › Replication: the receiving side ("Accept from another
 * server"). Sending to another server is the Backup app's Replication tab.
 */
export function ReplicationPage() {
  const shell = useShell();
  return (
    <>
      <PageHeader
        title="Replication"
        subtitle="Let another HardyOS server send its shared folders, apps and VMs here. To send this server's to another one, use the Backup app."
      />
      <p className="small">
        <Button variant="ghost" size="sm" onClick={() => shell.openApp("os.hardy.backup", { tab: "replication" })}>
          Send to another server: open Backup › Replication
        </Button>
      </p>
      <AcceptPanel />
    </>
  );
}
