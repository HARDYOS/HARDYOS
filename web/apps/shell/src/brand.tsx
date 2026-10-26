/**
 * HardyOS brand assets. The SVG sources live in /brand at the repo root and
 * are served from /brand/ (web/apps/shell/public/brand).
 */

/** The hexagon "H" mark without a background, for dark glass surfaces. */
export function BrandMark({ size = 24, label }: { size?: number; label?: string }) {
  return (
    <img
      className="brand-mark"
      src={size < 28 ? "/brand/hardyos-mark-small.svg" : "/brand/hardyos-mark.svg"}
      width={Math.round(size * (380 / 432))}
      height={size}
      alt={label ?? ""}
      aria-hidden={label ? undefined : true}
      draggable={false}
    />
  );
}

/** The app icon (mark on its rounded tile), for hero spots. */
export function BrandIcon({ size = 64 }: { size?: number }) {
  return <img className="brand-icon" src="/brand/hardyos-icon.svg" width={size} height={size} alt="" aria-hidden draggable={false} />;
}

/** "HARDYOS" in the logo's lettering: white HARDY, gradient OS. */
export function Wordmark({ className = "" }: { className?: string }) {
  return (
    <span className={`wordmark ${className}`} aria-label="HardyOS">
      HARDY<span className="wordmark__os">OS</span>
    </span>
  );
}
