import type { Job, Share, ShareServices } from "@hardy/api-client";
import { api, unwrap } from "../../api";

/** Waits for a job a request started; throws its error if it fails. */
export async function jobDone(start: Promise<{ job: Job }>): Promise<Job> {
  const { job } = await start;
  for (;;) {
    const j = await unwrap(api.GET("/jobs/{id}", { params: { path: { id: job.id } } }));
    if (j.state === "succeeded") return j;
    if (j.state === "failed" || j.state === "cancelled") throw new Error(j.error || `${j.title}: ${j.state}`);
    await new Promise((r) => setTimeout(r, 500));
  }
}

export const DEFAULT_SERVICES: ShareServices = {
  smb: { enabled: true, timeMachine: false, timeMachineMaxBytes: 0, previousVersions: true },
  nfs: { enabled: false, clients: [] },
  snapshots: { hourly: 24, daily: 14, weekly: 8, monthly: 6 },
};

/**
 * Changes one part of a shared folder's services. The folder is read again
 * first so another section's saved change (SMB, NFS, snapshots) isn't
 * overwritten with what this dialog loaded.
 */
export async function saveServices(id: string, change: (s: ShareServices) => ShareServices): Promise<Share> {
  const fresh = await unwrap(api.GET("/shares/{id}", { params: { path: { id } } }));
  const services = change(fresh.services ?? DEFAULT_SERVICES);
  await jobDone(unwrap(api.PATCH("/shares/{id}", { params: { path: { id } }, body: { services } })));
  return { ...fresh, services };
}
