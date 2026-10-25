import { useWM } from "../wm/store";
import { appById, type AppProps } from "../shell";
import { EmptyState } from "../ui";

/** Placeholder window for apps planned in later phases. */
export default function ComingSoon({ windowId }: AppProps) {
  const appId = useWM((s) => s.windows.find((w) => w.id === windowId)?.appId);
  const app = appId ? appById(appId) : undefined;
  return (
    <div className="pad center-fill">
      <EmptyState
        icon={app && <span className="app-tile" style={{ background: app.color }}>{app.glyph(30)}</span>}
        title={`${app?.name ?? "This app"} is on the way`}
      >
        It arrives with {app?.comingIn ?? "a later build"}.
      </EmptyState>
    </div>
  );
}
