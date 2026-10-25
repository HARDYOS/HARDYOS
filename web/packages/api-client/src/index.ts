import createClient from "openapi-fetch";
import type { components, paths } from "./schema.gen";

export type { components, paths };
export type Health = components["schemas"]["Health"];
export type VersionInfo = components["schemas"]["VersionInfo"];
export type ApiError = components["schemas"]["Error"];

/** Creates a typed client for the hardyd API. */
export function createApiClient(baseUrl = "/api/v1", fetchImpl?: typeof fetch) {
  return createClient<paths>({
    baseUrl,
    credentials: "same-origin",
    // Resolve fetch per call so tests and service workers that replace it are honored.
    fetch: fetchImpl ?? ((req: Request) => globalThis.fetch(req)),
  });
}

export type ApiClient = ReturnType<typeof createApiClient>;
