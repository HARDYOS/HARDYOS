import { createApiClient } from "@hardy/api-client";

/** The shared hardyd client for the whole desktop, anchored to the page's origin. */
export const api = createApiClient(new URL("/api/v1", window.location.origin).toString());
