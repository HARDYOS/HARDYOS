import { Suspense, useState } from "react";
import type { AppProps } from "../../shell";
import { Loading } from "../../ui";
import { Destinations } from "./Destinations";
import { History } from "./History";
import { RebuildBanner } from "./Rebuild";
import { RestoreBrowser } from "./Restore";
import { EXTRA_TABS, type BackupTab } from "./tabs";
import { Tasks } from "./Tasks";
import "./backup.css";

/** The built-in tabs, in order; EXTRA_TABS (replication, ...) follow. */
export const BUILTIN_TABS: BackupTab[] = [
  { id: "tasks", label: "Tasks", component: Tasks },
  { id: "restore", label: "Restore", component: RestoreBrowser },
  { id: "destinations", label: "Destinations", component: Destinations },
  { id: "history", label: "History", component: History },
];

export default function Backup({ args }: AppProps) {
  return <BackupView initial={args?.tab} />;
}

export function BackupView({ initial }: { initial?: string }) {
  const tabs = [...BUILTIN_TABS, ...EXTRA_TABS];
  const [tab, setTab] = useState(() => (tabs.some((t) => t.id === initial) ? initial! : "tasks"));
  const [tabArgs, setTabArgs] = useState<Record<string, string>>({});
  const go = (id: string, a: Record<string, string> = {}) => {
    setTab(id);
    setTabArgs(a);
  };
  const Current = (tabs.find((t) => t.id === tab) ?? tabs[0]!).component;
  return (
    <div className="bk">
      <header className="bk-head">
        <div className="bk-head__brand">
          <span className="bk-head__mark" aria-hidden="true">
            <CloudGlyph />
          </span>
          <div>
            <h1 className="bk-head__title">Backup</h1>
            <p className="bk-head__sub">Versioned, encrypted backups in the cloud, restorable file by file or as a whole.</p>
          </div>
        </div>
        <div className="bk-tabs" role="tablist" aria-label="Backup sections">
          {tabs.map((t) => (
            <button
              key={t.id}
              type="button"
              role="tab"
              id={`bk-tab-${t.id}`}
              aria-selected={tab === t.id}
              aria-controls="bk-panel"
              className={`bk-tab ${tab === t.id ? "is-active" : ""}`}
              onClick={() => go(t.id)}
            >
              {t.label}
            </button>
          ))}
        </div>
      </header>
      <RebuildBanner />
      <div className="bk-body" role="tabpanel" id="bk-panel" aria-labelledby={`bk-tab-${tab}`}>
        <Suspense fallback={<Loading />}>
          <Current go={go} args={tabArgs} />
        </Suspense>
      </div>
    </div>
  );
}

export function CloudGlyph({ size = 22 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M7 18h10a4 4 0 0 0 .5-7.97A6 6 0 0 0 6.1 9.5 4.25 4.25 0 0 0 7 18z" />
      <path d="M12 11v5M9.5 13.5 12 11l2.5 2.5" />
    </svg>
  );
}
