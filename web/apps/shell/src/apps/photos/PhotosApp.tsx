import { useQuery } from "@tanstack/react-query";
import { api, unwrap } from "../../api";
import { ExternalIcon, PhotoIcon } from "../../icons";
import { type AppProps, useShell } from "../../shell";
import { Button, EmptyState, ErrorBox, Loading } from "../../ui";
import { AppFrameView, openInNewTab } from "../store/AppFrame";

/**
 * The desktop's Photos: the Immich app HardyOS sets up (docs/photos.md),
 * in a window. HardyOS's sign-in page can't be shown inside another page,
 * so the first sign-in with HardyOS happens in a tab of its own; the
 * window then has the Immich session too.
 */
export default function PhotosApp(_: AppProps) {
  const shell = useShell();
  const q = useQuery({ queryKey: ["photos-info"], queryFn: () => unwrap(api.GET("/photos")) });
  if (q.isPending) return <Loading label="Opening Photos…" />;
  if (q.isError) return <ErrorBox error={q.error} onRetry={() => q.refetch()} />;
  const info = q.data;
  const admin = shell.user.role === "admin";
  if (!info.installed) {
    return (
      <div className="pad">
        <EmptyState
          icon={<PhotoIcon size={28} />}
          title="Photos isn't set up yet"
          action={
            admin ? (
              <Button variant="primary" onClick={() => shell.openApp("os.hardy.store")}>
                Install Immich
              </Button>
            ) : undefined
          }
        >
          {admin
            ? "Photos is Immich, from the App Store. Install it, then choose its settings in Control Panel › Photos."
            : "Ask an administrator to install Immich from the App Store."}
        </EmptyState>
      </div>
    );
  }
  if (!info.mayUse) {
    return (
      <div className="pad">
        <EmptyState icon={<PhotoIcon size={28} />} title="You can't use Photos">
          Ask an administrator to let you use Immich (App Store › Immich › Who can use it).
        </EmptyState>
      </div>
    );
  }
  return (
    <div className="photos-app">
      {info.sso && (
        <div className="photos-app__hint small muted">
          First time? Sign in with HardyOS in a tab of its own, then come back here.
          <Button size="sm" variant="ghost" onClick={() => openInNewTab(info.appId, "Photos")}>
            <ExternalIcon size={14} /> Sign in
          </Button>
        </div>
      )}
      <AppFrameView id={info.appId} name="Photos" />
    </div>
  );
}
