import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, errorMessage, unwrap } from "../../api";
import { Alert, Card, Toggle } from "../../ui";

/** The browser terminal's on/off switch. */
export function TerminalSwitch() {
  const qc = useQueryClient();
  const st = useQuery({ queryKey: ["terminal-settings"], queryFn: () => unwrap(api.GET("/terminal/settings")) });
  const set = useMutation({
    mutationFn: (enabled: boolean) => unwrap(api.PUT("/terminal/settings", { body: { enabled } })),
    onSuccess: (r) => qc.setQueryData(["terminal-settings"], r),
  });
  if (!st.data) return null;
  return (
    <Card title="Terminal">
      <Toggle
        label="Allow the browser terminal"
        description="Administrators can open a root shell from the desktop after entering their password again. Turn it off if nobody needs it; SSH still works."
        checked={st.data.enabled}
        disabled={set.isPending}
        onChange={(v) => set.mutate(v)}
      />
      {set.error != null && <Alert tone="bad">{errorMessage(set.error)}</Alert>}
    </Card>
  );
}
