import { useMutation } from "@tanstack/react-query";
import { useState } from "react";
import { api, errorMessage, unwrap } from "../../api";
import { duration } from "../../format";
import { useHardware, usePools, useSystemInfo } from "../../hooks/queries";
import { CpuIcon, ShieldIcon, StorageIcon, UsersIcon } from "../../icons";
import { useShell } from "../../shell";
import { Alert, Button, Card, PageHeader, Stat } from "../../ui";
import { JobProgress } from "../shared";

export function Overview({ onNavigate }: { onNavigate: (section: string) => void }) {
  const { openApp } = useShell();
  const info = useSystemInfo();
  const pools = usePools();
  const hw = useHardware();
  const [jobId, setJobId] = useState<string | null>(null);
  const selfTest = useMutation({
    mutationFn: () => unwrap(api.POST("/system/self-test")),
    onSuccess: (job) => setJobId(job.id),
  });

  const poolList = pools.data ?? [];
  const unhealthy = poolList.filter((p) => p.health !== "ONLINE");
  const advisories = hw.data?.capabilities.advisories ?? [];

  return (
    <>
      <PageHeader
        title="Overview"
        subtitle={info.data ? `${info.data.hostname} · HardyOS ${info.data.version} · ${info.data.os || "Debian"}` : "Loading…"}
      />
      <div className="grid-3">
        <Stat label="System" value="Healthy" tone="good" sub={info.data ? `Up ${duration(info.data.uptimeSecs)}` : undefined} />
        <Stat
          label="Storage"
          value={pools.isPending ? "…" : poolList.length === 0 ? "No pool yet" : unhealthy.length ? `${unhealthy.length} need attention` : `${poolList.length} pool${poolList.length > 1 ? "s" : ""} online`}
          tone={poolList.length === 0 ? "neutral" : unhealthy.length ? "warn" : "good"}
          sub={poolList.length === 0 ? "Create one in Storage Manager" : undefined}
        />
        <Stat label="Kernel" value={<span className="mono" style={{ fontSize: 14 }}>{info.data?.kernel ?? "…"}</span>} sub={info.data?.os} />
      </div>

      {advisories.length > 0 && (
        <div className="stack">
          {advisories.map((a) => (
            <Alert key={a} tone="info">
              {a}
            </Alert>
          ))}
        </div>
      )}

      <span className="section-label">Settings</span>
      <div className="grid-2">
        <SettingTile icon={<StorageIcon size={18} />} tone="good" title="Storage" desc="Pools, disks, snapshots" onClick={() => openApp("os.hardy.storage")} />
        <SettingTile icon={<UsersIcon size={18} />} tone="violet" title="Users & Groups" desc="Local accounts and roles" onClick={() => onNavigate("users")} />
        <SettingTile icon={<CpuIcon size={18} />} tone="neutral" title="Hardware" desc="Devices, IOMMU, capabilities" onClick={() => onNavigate("hardware")} />
        <SettingTile icon={<ShieldIcon size={18} />} tone="bad" title="Security" desc="Audit log of every change" onClick={() => onNavigate("security")} />
      </div>

      <Card
        title="System self-test"
        actions={
          <Button size="sm" onClick={() => { setJobId(null); selfTest.mutate(); }} busy={selfTest.isPending}>
            Run self-test
          </Button>
        }
      >
        <p className="muted small" style={{ margin: 0 }}>
          Checks that the control plane, the job system and the privileged helper are all working together.
        </p>
        {selfTest.error && <Alert tone="bad">{errorMessage(selfTest.error)}</Alert>}
        {jobId && <JobProgress id={jobId} />}
      </Card>
    </>
  );
}

const TILE_COLORS: Record<string, [string, string]> = {
  good: ["rgba(52,211,153,0.16)", "#5EE3B1"],
  violet: ["rgba(167,139,250,0.18)", "#B9A4FF"],
  neutral: ["rgba(148,163,184,0.18)", "#CBD5E1"],
  bad: ["rgba(248,113,113,0.16)", "#FCA5A5"],
};

function SettingTile({ icon, tone, title, desc, onClick }: { icon: React.ReactNode; tone: string; title: string; desc: string; onClick: () => void }) {
  const [bg, fg] = TILE_COLORS[tone] ?? TILE_COLORS.neutral!;
  return (
    <button type="button" className="card" style={{ flexDirection: "row", alignItems: "flex-start", gap: 12, textAlign: "left", cursor: "pointer" }} onClick={onClick}>
      <span style={{ width: 36, height: 36, borderRadius: 10, background: bg, color: fg, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>{icon}</span>
      <span style={{ display: "flex", flexDirection: "column", gap: 3 }}>
        <strong>{title}</strong>
        <span className="small muted">{desc}</span>
      </span>
    </button>
  );
}
