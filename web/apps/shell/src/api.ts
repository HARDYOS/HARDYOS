import { type ApiError, createApiClient } from "@hardy/api-client";
import { QueryCache, QueryClient } from "@tanstack/react-query";

/** The shared hardyd client for the whole desktop, anchored to the page's origin. */
export const api = createApiClient(new URL("/api/v1", window.location.origin).toString());

/** A failed API call with hardyd's error code and message. */
export class ApiFailure extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "ApiFailure";
  }
}

interface FetchResult<T> {
  data?: T;
  error?: ApiError | unknown;
  response: Response;
}

/** Awaits an openapi-fetch call and returns its data, throwing ApiFailure on errors. */
export async function unwrap<T>(call: Promise<FetchResult<T>>): Promise<T> {
  let r: FetchResult<T>;
  try {
    r = await call;
  } catch {
    throw new ApiFailure(0, "network", "Can't reach the server. Check that it's on and connected.");
  }
  if (!r.response.ok) {
    const e = (r.error ?? {}) as Partial<ApiError>;
    throw new ApiFailure(r.response.status, e.code ?? "error", e.message ?? r.response.statusText);
  }
  return r.data as T;
}

/** Message for showing an unknown error to a person. */
export function errorMessage(err: unknown): string {
  if (err instanceof ApiFailure) return err.message;
  if (err instanceof Error) return err.message;
  return "Something went wrong.";
}

export const queryClient = new QueryClient({
  queryCache: new QueryCache({
    onError: (err) => {
      // A 401 anywhere means the session ended: re-check who we are, which shows the sign-in screen.
      if (err instanceof ApiFailure && err.status === 401) {
        void queryClient.invalidateQueries({ queryKey: ["me"] });
      }
    },
  }),
  defaultOptions: {
    queries: {
      retry: (count, err) => !(err instanceof ApiFailure && err.status >= 400 && err.status < 500) && count < 2,
      refetchOnWindowFocus: false,
      staleTime: 5_000,
    },
  },
});
