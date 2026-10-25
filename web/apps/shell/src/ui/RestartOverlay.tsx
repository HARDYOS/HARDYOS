import { useEffect, useState } from "react";
import { BrandMark } from "../brand";
import { Spinner } from ".";

/**
 * Full-screen "restarting" state. Waits for the server to go away and come
 * back, then reloads the page (which shows the sign-in screen).
 */
export function RestartOverlay({ message = "Restarting HardyOS…" }: { message?: string }) {
  const [phase, setPhase] = useState<"going" | "down" | "slow">("going");
  useEffect(() => {
    let down = false;
    const started = Date.now();
    const t = setInterval(async () => {
      try {
        const r = await fetch("/api/v1/health", { cache: "no-store" });
        if (r.ok && down) window.location.reload();
      } catch {
        if (!down) {
          down = true;
          setPhase("down");
        }
      }
      if (Date.now() - started > 5 * 60_000) setPhase("slow");
    }, 3000);
    return () => clearInterval(t);
  }, []);
  return (
    <div className="restart-overlay" role="alertdialog" aria-live="assertive" aria-label={message}>
      <div className="restart-overlay__card glass">
        <BrandMark size={56} />
        <h2>{message}</h2>
        <p className="muted">
          {phase === "going" && "Saving settings and shutting down."}
          {phase === "down" && "The server is starting. This page reloads when it's back, usually within two minutes."}
          {phase === "slow" &&
            "This is taking longer than usual. If the server doesn't come back, check its screen: it may be waiting at the boot menu."}
        </p>
        <Spinner size={22} />
      </div>
    </div>
  );
}
