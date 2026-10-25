import { LoginScreen, SetupScreen } from "./auth/AuthScreens";
import { Desktop } from "./desktop/Desktop";
import { useMe, useSetupStatus } from "./hooks/session";
import { Installer, useInstallerStatus } from "./installer/Installer";
import { Alert, Button, Loading } from "./ui";

/** Decides between the live installer, first-run setup, sign-in and the desktop. */
export function App() {
  const installer = useInstallerStatus();
  // An older server without the installer endpoint simply isn't an installer.
  const installerKnown = !installer.isPending;
  const isInstaller = installer.data?.active === true;
  const setup = useSetupStatus(installerKnown && !isInstaller);
  const me = useMe(installerKnown && !isInstaller);

  if (isInstaller) return <Installer status={installer.data!} />;
  if (!installerKnown || setup.isPending || me.isPending) {
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
