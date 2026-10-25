import type { User } from "@hardy/api-client";
import { Component, type ErrorInfo, type ReactNode, Suspense, useMemo } from "react";
import { type ShellContextValue, ShellContext, appById } from "../shell";
import { Alert, Button, Loading } from "../ui";
import { toast } from "../ui/toasts";
import { openApp } from "./open";
import { useWM } from "./store";
import { Window } from "./Window";

class AppErrorBoundary extends Component<{ children: ReactNode; name: string }, { error: Error | null }> {
  state = { error: null as Error | null };
  static getDerivedStateFromError(error: Error) {
    return { error };
  }
  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error(`app ${this.props.name} crashed`, error, info);
  }
  render() {
    if (this.state.error) {
      return (
        <div className="pad">
          <Alert
            tone="bad"
            title={`${this.props.name} hit an error`}
            action={<Button size="sm" onClick={() => this.setState({ error: null })}>Reload app</Button>}
          >
            {this.state.error.message}
          </Alert>
        </div>
      );
    }
    return this.props.children;
  }
}

/** Renders every open window with its app inside a shell context. */
export function WindowLayer({ user }: { user: User }) {
  const windows = useWM((s) => s.windows);
  const focusedId = useWM((s) => s.focusedId);
  return (
    <>
      {windows.map((w) => (
        <WindowHost key={w.id} id={w.id} user={user} focused={focusedId === w.id} />
      ))}
    </>
  );
}

function WindowHost({ id, user, focused }: { id: string; user: User; focused: boolean }) {
  const win = useWM((s) => s.windows.find((w) => w.id === id));
  const app = win ? appById(win.appId) : undefined;

  const bridge = useMemo<ShellContextValue>(
    () => ({
      user,
      windowId: id,
      openApp: (appId, args) => openApp(appId, user, args),
      notify: (n) => toast(n.level ?? "info", n.title, n.body),
      setTitle: (title) => useWM.getState().setTitle(id, title),
      close: () => useWM.getState().close(id),
    }),
    [id, user],
  );

  if (!win || !app) return null;
  const AppComponent = app.component;
  return (
    <Window win={win} focused={focused}>
      <ShellContext.Provider value={bridge}>
        <AppErrorBoundary name={app.name}>
          <Suspense fallback={<Loading label={`Opening ${app.name}…`} />}>
            <AppComponent windowId={id} args={win.args} />
          </Suspense>
        </AppErrorBoundary>
      </ShellContext.Provider>
    </Window>
  );
}
