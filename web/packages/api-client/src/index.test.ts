import { describe, expect, it } from "vitest";
import { createApiClient } from "./index";

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
});
