import { describe, expect, it } from "vitest";
import { CSRF_HEADER, createApiClient, eventsUrl } from "./index";

describe("createApiClient", () => {
  it("calls the version endpoint and returns typed data", async () => {
    const fakeFetch = async (input: Request | string | URL) => {
      const url = input instanceof Request ? input.url : String(input);
      expect(url).toContain("/api/v1/version");
      return new Response(
        JSON.stringify({ version: "0.1.0", commit: "abc", goVersion: "go1.24", os: "linux", arch: "amd64" }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    };
    const api = createApiClient("http://nas.local/api/v1", fakeFetch as typeof fetch);
    const { data, error } = await api.GET("/version");
    expect(error).toBeUndefined();
    expect(data?.version).toBe("0.1.0");
  });

  it("sends the CSRF header on state-changing requests", async () => {
    let seen: string | null = null;
    const fakeFetch = async (input: Request | string | URL) => {
      if (input instanceof Request) seen = input.headers.get(CSRF_HEADER);
      return new Response(JSON.stringify({ code: "bad_credentials", message: "nope" }), {
        status: 401,
        headers: { "Content-Type": "application/json" },
      });
    };
    const api = createApiClient("http://nas.local/api/v1", fakeFetch as typeof fetch);
    const { error } = await api.POST("/auth/login", { body: { username: "cade", password: "x" } });
    expect(seen).toBe("1");
    expect(error?.code).toBe("bad_credentials");
  });
});

describe("eventsUrl", () => {
  it("uses wss for https pages and ws for http", () => {
    expect(eventsUrl("https://nas.local")).toBe("wss://nas.local/api/v1/events");
    expect(eventsUrl("http://localhost:5173")).toBe("ws://localhost:5173/api/v1/events");
  });
});
