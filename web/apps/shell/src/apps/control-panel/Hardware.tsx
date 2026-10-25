import { bytes } from "../../format";
import { useHardware } from "../../hooks/queries";
import { CheckIcon } from "../../icons";
import { Alert, Badge, Card, ErrorBox, Loading, PageHeader, Stat } from "../../ui";

export function Hardware() {
  const hw = useHardware();
  if (hw.isPending) return <Loading />;
  if (hw.isError) return <ErrorBox error={hw.error} onRetry={() => hw.refetch()} />;
  const { system, capabilities: caps, disks } = hw.data;
  const ecc = system.memory.ecc;

  const capList: [string, boolean, string][] = [
    ["Virtual machines", caps.virtualization, system.cpu.virtualization === "vt-x" ? "Intel VT-x" : system.cpu.virtualization === "amd-v" ? "AMD-V" : "Not available"],
    ["PCIe passthrough", caps.pciePassthrough, system.iommuEnabled ? `${system.iommuGroups} IOMMU groups` : "IOMMU off"],
    ["Hardware video transcoding", caps.hardwareTranscode, system.gpus.map((g) => g.vendor).join(", ") || "No GPU found"],
    ["Special vdev (metadata on SSD)", caps.specialVdev, "Needs 2 unused SSDs"],
    ["Log device (SLOG)", caps.slog, "Needs 2 unused SSDs"],
    ["Read cache (L2ARC)", caps.l2arc, "Needs a spare SSD and 32 GB+ RAM"],
  ];

  return (
    <>
      <PageHeader title="Hardware" subtitle={system.virtual ? "Running inside a virtual machine" : "What HardyOS detected on this machine"} />
      <div className="grid-4">
        <Stat label="Processor" value={<span style={{ fontSize: 14 }}>{system.cpu.model || "Unknown CPU"}</span>} sub={`${system.cpu.threads} threads`} />
        <Stat label="Memory" value={bytes(system.memory.totalBytes, 0)} sub={ecc === true ? "ECC" : ecc === false ? "Non-ECC" : "ECC unknown"} />
        <Stat label="Disks" value={String(disks.length)} sub={`${disks.filter((d) => d.usage === "free" || d.usage === "has-data").length} unused`} />
        <Stat label="ZFS cache limit" value={bytes(caps.arcMaxBytes, 0)} sub="Leaves room for apps and VMs" />
      </div>

      {caps.advisories.map((a) => (
        <Alert key={a} tone="info">
          {a}
        </Alert>
      ))}

      <Card title="Capabilities">
        <ul style={{ listStyle: "none", margin: 0, padding: 0, display: "grid", gap: 10 }}>
          {capList.map(([name, ok, detail]) => (
            <li key={name} className="row" style={{ flexWrap: "nowrap" }}>
              <span style={{ width: 22, display: "inline-flex", color: ok ? "var(--hos-good)" : "var(--hos-text-faint)" }}>
                {ok ? <CheckIcon size={16} /> : <span aria-hidden="true">–</span>}
              </span>
              <span className="grow">{name}</span>
              <span className="small muted">{detail}</span>
              <span className="sr-only">{ok ? "available" : "not available"}</span>
            </li>
          ))}
        </ul>
      </Card>

      <div className="grid-2">
        <Card title="Graphics">
          {system.gpus.length === 0 ? (
            <p className="muted small" style={{ margin: 0 }}>No GPU found. Video and photo processing will use the CPU.</p>
          ) : (
            <dl className="kv">
              {system.gpus.map((g) => (
                <div key={g.address} style={{ display: "contents" }}>
                  <dt className="mono">{g.address}</dt>
                  <dd>
                    {g.vendor.toUpperCase()} {g.deviceId} · driver {g.driver || "none"}
                    {g.iommuGroup != null && <span className="cell-sub">IOMMU group {g.iommuGroup}</span>}
                  </dd>
                </div>
              ))}
            </dl>
          )}
        </Card>
        <Card title="Network">
          {system.nics.length === 0 ? (
            <p className="muted small" style={{ margin: 0 }}>No physical network interfaces found.</p>
          ) : (
            <dl className="kv">
              {system.nics.map((n) => (
                <div key={n.name} style={{ display: "contents" }}>
                  <dt className="mono">{n.name}</dt>
                  <dd>
                    {n.up ? <Badge tone="good">up</Badge> : <Badge tone="neutral">down</Badge>}{" "}
                    {n.speedMbps > 0 ? (n.speedMbps >= 1000 ? `${n.speedMbps / 1000} GbE` : `${n.speedMbps} Mb/s`) : ""}
                    <span className="cell-sub mono">
                      {n.mac} · {n.driver}
                    </span>
                  </dd>
                </div>
              ))}
            </dl>
          )}
        </Card>
      </div>
    </>
  );
}
