import type { VM, VMKeptDisk, VMTemplate } from "@hardy/api-client";
import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, errorMessage, unwrap } from "../../api";
import { bytes } from "../../format";
import { DiscIcon, PlayIcon, PlusIcon, PowerIcon, ScreenIcon, TrashIcon, VMIcon } from "../../icons";
import { type AppProps, useShell } from "../../shell";
import { Alert, AppLayout, Badge, Button, Card, EmptyState, ErrorBox, IconButton, Loading, type NavItem, PageHeader, SideNav } from "../../ui";
import { ConfirmDialog } from "../../ui/Dialog";
import { toast } from "../../ui/toasts";
import { Library } from "./Library";
import { NewVM } from "./NewVM";
import { Meter, StateBadge, VMGlyph } from "./parts";
import { VMPage, type VMTab } from "./VMPage";
import { consoleWindowId, isOn, memory, osLabel, useCapabilities, useTemplates, useVMs, vmAction, vmKeys } from "./vmApi";
import "./vms.css";

type Section = "list" | "new" | "library";

export default function VirtualMachines(_: AppProps) {
  const shell = useShell();
  return (
    <VirtualMachinesView
      onOpenConsole={(vm) => shell.openApp(consoleWindowId(vm.id), { id: vm.id, title: `${vm.name}: screen` })}
      onOpenFiles={() => shell.openApp("os.hardy.files", { share: "isos" })}
    />
  );
}

export function VirtualMachinesView({ onOpenConsole, onOpenFiles }: { onOpenConsole: (vm: VM) => void; onOpenFiles?: () => void }) {
  const [section, setSection] = useState<Section>("list");
  const [selected, setSelected] = useState<string | null>(null);
  const [tab, setTab] = useState<VMTab>("overview");
  const vms = useVMs();
  const templates = useTemplates();
  const running = (vms.data?.vms ?? []).filter((v) => v.state === "running").length;
  const items: NavItem[] = [
    { id: "list", label: "Virtual machines", icon: <VMIcon size={16} />, badge: running > 0 ? <Badge tone="good">{running}</Badge> : undefined },
    { id: "library", label: "ISO library", icon: <DiscIcon size={16} /> },
  ];
  const go = (s: Section) => {
    setSection(s);
    setSelected(null);
  };
  const open = (id: string, t: VMTab = "overview") => {
    setSection("list");
    setSelected(id);
    setTab(t);
  };
  return (
    <AppLayout
      nav={
        <SideNav
          label="Virtual machines sections"
          items={items}
          active={section === "new" ? "list" : section}
          onSelect={(s) => go(s as Section)}
          footer={
            <Button variant="primary" className="btn--block" onClick={() => go("new")}>
              <PlusIcon size={15} /> New VM
            </Button>
          }
        />
      }
    >
      {section === "new" && <NewVM onCancel={() => go("list")} onCreated={(id) => open(id)} openFiles={onOpenFiles} />}
      {section === "library" && <Library openFiles={onOpenFiles} />}
      {section === "list" &&
        (selected ? (
          <VMPage id={selected} templates={templates.data ?? []} tab={tab} onTab={setTab} onBack={() => setSelected(null)} onOpenConsole={onOpenConsole} />
        ) : vms.isPending ? (
          <Loading />
        ) : vms.isError ? (
          <ErrorBox error={vms.error} onRetry={() => vms.refetch()} />
        ) : (
          <VMList vms={vms.data.vms} kept={vms.data.kept} templates={templates.data ?? []} onNew={() => go("new")} onOpen={open} onOpenConsole={onOpenConsole} />
        ))}
    </AppLayout>
  );
}

function VMList({
  vms,
  kept,
  templates,
  onNew,
  onOpen,
  onOpenConsole,
}: {
  vms: VM[];
  kept: VMKeptDisk[];
  templates: VMTemplate[];
  onNew: () => void;
  onOpen: (id: string, tab?: VMTab) => void;
  onOpenConsole: (vm: VM) => void;
}) {
  const caps = useCapabilities();
  const qc = useQueryClient();
  const [pending, setPending] = useState<Record<string, boolean>>({});
  const [deletingKept, setDeletingKept] = useState<VMKeptDisk | null>(null);
  const act = async (vm: VM, a: "start" | "stop") => {
    setPending((p) => ({ ...p, [vm.id]: true }));
    try {
      await vmAction(vm.id, a);
      toast("info", a === "start" ? `Starting ${vm.name}` : `Shutting down ${vm.name}`);
      setTimeout(() => void qc.invalidateQueries({ queryKey: vmKeys.all }), 800);
    } catch (e) {
      toast("error", "That didn't work", errorMessage(e));
    } finally {
      setTimeout(() => setPending((p) => ({ ...p, [vm.id]: false })), 1500);
    }
  };
  const sorted = [...vms].sort((a, b) => Number(isOn(b)) - Number(isOn(a)) || a.name.localeCompare(b.name));
  const used = vms.filter((v) => v.state === "running").reduce((s, v) => s + v.memory.mb, 0);
  return (
    <div className="stack">
      <PageHeader
        title="Virtual machines"
        subtitle={
          vms.length > 0 && caps.data ? (
            <>
              {vms.filter((v) => v.state === "running").length} of {vms.length} running · {memory(used)} of {memory(caps.data.memoryMB)} memory given to
              running VMs
            </>
          ) : (
            "Whole computers inside your server: Windows, Linux, Home Assistant, a router…"
          )
        }
        actions={
          <Button variant="primary" onClick={onNew}>
            <PlusIcon size={15} /> New VM
          </Button>
        }
      />
      {caps.data && !caps.data.supported && (
        <Alert tone="warn" title="VMs can't run on this server yet">
          {caps.data.problem}
        </Alert>
      )}
      {vms.length === 0 ? (
        <EmptyState
          icon={<VMIcon size={30} />}
          title="No virtual machines yet"
          action={
            <Button variant="primary" onClick={onNew}>
              <PlusIcon size={15} /> Create your first VM
            </Button>
          }
        >
          Run Windows, a Linux server, Home Assistant or a firewall on this server. HardyOS sets up the disks, network and drivers.
        </EmptyState>
      ) : (
        <div className="vm-grid">
          {sorted.map((vm) => {
            const on = vm.state === "running";
            return (
              <article
                key={vm.id}
                className={`vm-card ${on ? "is-running" : ""}`}
                aria-label={vm.name}
                tabIndex={0}
                onClick={() => onOpen(vm.id)}
                onKeyDown={(e) => e.key === "Enter" && e.currentTarget === e.target && onOpen(vm.id)}
              >
                <div className="vm-card__head">
                  <VMGlyph template={vm.template} on={on} />
                  <div style={{ minWidth: 0, flex: 1 }}>
                    <div className="vm-card__name">{vm.name}</div>
                    <div className="vm-card__sub">
                      {osLabel(vm, templates)}
                      {on && vm.addresses[0] ? (
                        <>
                          {" "}
                          · <span className="mono">{vm.addresses[0]}</span>
                        </>
                      ) : null}
                    </div>
                  </div>
                  <StateBadge state={vm.state} />
                </div>
                <div className="vm-card__meters">
                  <Meter label="CPU" value={on ? `${Math.round(vm.cpuPercent)}%` : `${vm.cpu.cores * vm.cpu.threads} vCPU`} percent={on ? vm.cpuPercent : 0} />
                  <Meter
                    label="Memory"
                    value={on && vm.memoryUsedMB ? `${memory(vm.memoryUsedMB)} / ${memory(vm.memory.mb)}` : memory(vm.memory.mb)}
                    percent={on && vm.memoryUsedMB ? (vm.memoryUsedMB / vm.memory.mb) * 100 : 0}
                  />
                </div>
                <div className="vm-card__foot" onClick={(e) => e.stopPropagation()}>
                  {isOn(vm) ? (
                    <>
                      <Button size="sm" onClick={() => onOpenConsole(vm)}>
                        <ScreenIcon size={14} /> Screen
                      </Button>
                      <Button size="sm" variant="ghost" busy={pending[vm.id]} onClick={() => act(vm, "stop")}>
                        <PowerIcon size={14} /> Shut down
                      </Button>
                    </>
                  ) : (
                    <Button size="sm" variant="primary" busy={pending[vm.id]} onClick={() => act(vm, "start")}>
                      <PlayIcon size={14} /> Start
                    </Button>
                  )}
                  <span className="grow" />
                  {vm.restartNeeded && <Badge tone="warn">restart</Badge>}
                  {vm.autostart.enabled && <span className="small muted">starts with the server</span>}
                </div>
              </article>
            );
          })}
        </div>
      )}
      {kept.length > 0 && (
        <Card title="Disks kept from deleted VMs">
          <div className="stack" style={{ gap: 6 }}>
            {kept.map((k) => (
              <div key={k.dataset} className="row" style={{ gap: 8 }}>
                <span className="mono grow">{k.dataset}</span>
                <span className="small muted mono">{bytes(k.bytes)}</span>
                <IconButton label={`Delete ${k.dataset}`} onClick={() => setDeletingKept(k)}>
                  <TrashIcon size={15} />
                </IconButton>
              </div>
            ))}
          </div>
        </Card>
      )}
      {deletingKept && (
        <ConfirmDialog
          title="Delete these disks?"
          confirmLabel="Delete"
          typeToConfirm={deletingKept.vm}
          onClose={() => setDeletingKept(null)}
          onConfirm={async () => {
            await unwrap(api.POST("/vms/kept/delete", { body: { dataset: deletingKept.dataset, confirm: deletingKept.vm } }));
            setTimeout(() => void qc.invalidateQueries({ queryKey: vmKeys.all }), 1000);
          }}
        >
          <p>
            The disks of the deleted VM {deletingKept.vm} ({bytes(deletingKept.bytes)}) are deleted for good.
          </p>
        </ConfirmDialog>
      )}
    </div>
  );
}
