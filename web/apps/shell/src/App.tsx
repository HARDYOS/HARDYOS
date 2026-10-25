import { LoginScreen, SetupScreen } from "./auth/AuthScreens";
import { Desktop } from "./desktop/Desktop";
import { useMe, useSetupStatus } from "./hooks/session";
import { Alert, Button, Loading } from "./ui";

/** Decides between first-run setup, sign-in and the desktop. */
export function App() {
  const setup = useSetupStatus();
  const me = useMe();

  if (setup.isPending || me.isPending) {
    return (
      <div className="lock-screen wallpaper">
        <Loading label="Starting HardyOS…" />
      </div>
    );
  }
  if (setup.isError || me.isError) {
    return (
      <div className="lock-screen wallpaper">
        <div className="lock-card glass">
          <Alert tone="bad" title="Can't reach the server" action={<Button onClick={() => { void setup.refetch(); void me.refetch(); }}>Try again</Button>}>
            The HardyOS control plane isn't answering. It may still be starting up.
          </Alert>
        </div>
      </div>
    );
  }
  if (setup.data?.needsAdmin) return <SetupScreen />;
  if (!me.data) return <LoginScreen />;
  return <Desktop user={me.data} />;
}
