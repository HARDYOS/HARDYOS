import createClient from "openapi-fetch";
import type { components, paths } from "./schema.gen";

export type { components, paths };
type S = components["schemas"];
export type Health = S["Health"];
export type VersionInfo = S["VersionInfo"];
export type ApiError = S["Error"];
export type User = S["User"];
export type Role = S["Role"];
export type Job = S["Job"];
export type JobState = S["JobState"];
export type AuditEntry = S["AuditEntry"];
export type SetupStatus = S["SetupStatus"];

/** Header every state-changing request must carry (hardyd's CSRF check). */
export const CSRF_HEADER = "X-HardyOS-Request";

/** Creates a typed client for the hardyd API. */
export function createApiClient(baseUrl = "/api/v1", fetchImpl?: typeof fetch) {
  return createClient<paths>({
    baseUrl,
    credentials: "same-origin",
    headers: { [CSRF_HEADER]: "1" },
    // Resolve fetch per call so tests and service workers that replace it are honored.
    fetch: fetchImpl ?? ((req: Request) => globalThis.fetch(req)),
  });
}

export type ApiClient = ReturnType<typeof createApiClient>;

/** Builds the WebSocket URL for the event stream relative to the page. */
export function eventsUrl(origin: string = globalThis.location?.origin ?? "http://localhost"): string {
  const u = new URL("/api/v1/events", origin);
  u.protocol = u.protocol === "https:" ? "wss:" : "ws:";
  return u.toString();
}
