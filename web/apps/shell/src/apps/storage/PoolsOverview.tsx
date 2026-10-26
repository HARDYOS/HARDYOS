import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, errorMessage, unwrap } from "../../api";
import { bytes } from "../../format";
import { isBootPool, usePools } from "../../hooks/queries";
import { StorageIcon } from "../../icons";
import { Alert, Badge, Button, Card, EmptyState, ErrorBox, Loading, PageHeader, Progress } from "../../ui";
import { toast } from "../../ui/toasts";
import { SystemPoolCard } from "./BootDisks";
import { healthTone } from "./StorageManager";

export function PoolsOverview({ onOpenPool, onCreate }: { onOpenPool: (p: string) => void; onCreate: () => void }) {
  const pools = usePools();
  const qc = useQueryClient();
  const importable = useQuery({ queryKey: ["importable"], queryFn: () => unwrap(api.GET("/storage/importable")), staleTime: 60_000 });
  const doImport = useMutation({
    mutationFn: (p: { pool: string; force: boolean }) => unwrap(api.POST("/storage/import", { body: p })),
    onSuccess: (_, p) => {
      toast("success", `Imported ${p.pool}`);
      void qc.invalidateQueries({ queryKey: ["pools"] });
      void qc.invalidateQueries({ queryKey: ["importable"] });
    },
  });

  if (pools.isPending) return <Loading />;
  if (pools.isError) return <ErrorBox error={pools.error} onRetry={() => pools.refetch()} />;
  const list = pools.data.filter((p) => !isBootPool(p.name));
  const system = pools.data.filter((p) => isBootPool(p.name));

  return (
    <>
      <PageHeader title="Storage" subtitle="Pools hold your data. Each one spreads data across several disks so a disk can fail without losing anything." />
      {list.length === 0 ? (
        <Card>
          <EmptyState
            icon={<StorageIcon size={40} />}
            title="No storage pool yet"
            action={
              <Button variant="primary" onClick={onCreate}>
                Create a pool
              </Button>
            }
          >
            HardyOS looks at your disks and suggests a safe layout. You can adjust it before anything is erased.
          </EmptyState>
        </Card>
      ) : (
        <div className="grid-2">
          {list.map((p) => (
            <button key={p.name} type="button" className="card" style={{ textAlign: "left", cursor: "pointer" }} onClick={() => onOpenPool(p.name)}>
              <div className="row row--between">
                <strong style={{ fontSize: 17 }}>{p.name}</strong>
                <Badge tone={healthTone(p.health)}>{p.health.toLowerCase()}</Badge>
              </div>
              <div className="row" style={{ alignItems: "baseline" }}>
                <span className="mono" style={{ fontSize: 24, fontWeight: 600 }}>
                  {bytes(p.allocBytes)}
                </span>
                <span className="small muted">used of {bytes(p.sizeBytes)}</span>
              </div>
              <Progress value={p.capacityPct} label={`${p.name} ${p.capacityPct}% full`} tone={p.capacityPct > 85 ? "warn" : "accent"} />
              <span className="small muted">
                {p.capacityPct}% full{p.fragmentation != null ? ` · ${p.fragmentation}% fragmented` : ""}
              </span>
            </button>
          ))}
        </div>
      )}

      {system.map((p) => (
        <SystemPoolCard key={p.name} pool={p} />
      ))}

      {importable.data && importable.data.length > 0 && (
        <Card title="Pools found on disks">
          <p className="small muted" style={{ margin: 0 }}>
            These disks hold pools that aren't imported, for example from another server or a previous install.
          </p>
          {importable.data.map((p) => (
            <div key={p.id} className="row row--between">
              <div>
                <strong>{p.name}</strong> <span className="small muted mono">{p.id}</span>
                {p.status && <span className="cell-sub">{p.status}</span>}
              </div>
              <Button
                size="sm"
                onClick={() => doImport.mutate({ pool: p.id, force: /another system/i.test(p.status) })}
                busy={doImport.isPending && doImport.variables?.pool === p.id}
              >
                Import
              </Button>
            </div>
          ))}
          {doImport.error && <Alert tone="bad">{errorMessage(doImport.error)}</Alert>}
        </Card>
      )}
    </>
  );
}
