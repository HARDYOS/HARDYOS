import type { VM } from "@hardy/api-client";
import type { ReactNode } from "react";
import { BoxIcon, DiscIcon, GamepadIcon, HomeIcon, PenguinIcon, RouterIcon, StorageIcon, VMIcon, WindowsIcon } from "../../icons";
import { Badge, Dot } from "../../ui";
import { STATE } from "./vmApi";

const GLYPHS: Record<string, (s: number) => ReactNode> = {
  windows11: (s) => <WindowsIcon size={s} />,
  windows10: (s) => <WindowsIcon size={s} />,
  linux: (s) => <PenguinIcon size={s} />,
  "linux-iso": (s) => <PenguinIcon size={s} />,
  gaming: (s) => <GamepadIcon size={s} />,
  haos: (s) => <HomeIcon size={s} />,
  opnsense: (s) => <RouterIcon size={s} />,
  truenas: (s) => <StorageIcon size={s} />,
  other: (s) => <DiscIcon size={s} />,
  import: (s) => <BoxIcon size={s} />,
};

export function templateGlyph(template: string, size = 20): ReactNode {
  return (GLYPHS[template] ?? ((s: number) => <VMIcon size={s} />))(size);
}

export function VMGlyph({ template, on, large }: { template: string; on?: boolean; large?: boolean }) {
  return (
    <span className={`vm-glyph ${on ? "vm-glyph--on" : ""} ${large ? "vm-glyph--lg" : ""}`} aria-hidden="true">
      {templateGlyph(template, large ? 28 : 20)}
    </span>
  );
}

export function StateBadge({ state }: { state: VM["state"] }) {
  const s = STATE[state] ?? STATE.unknown!;
  return (
    <Badge tone={s.tone}>
      <Dot tone={s.tone} /> {s.label}
    </Badge>
  );
}

export function Meter({ label, value, percent }: { label: string; value: string; percent: number }) {
  const p = Math.max(0, Math.min(100, percent));
  return (
    <div className="meter">
      <div className="meter__label">
        <span>{label}</span>
        <span className="meter__value">{value}</span>
      </div>
      <div className="meter__bar" role="meter" aria-label={label} aria-valuenow={Math.round(p)} aria-valuemin={0} aria-valuemax={100}>
        <span style={{ width: `${p}%` }} />
      </div>
    </div>
  );
}
