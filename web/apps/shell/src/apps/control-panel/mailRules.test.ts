import { describe, expect, it } from "vitest";
import { addressProblem, domainProblem, mailboxProblems, recordKey, settingsProblems } from "./mailRules";

describe("mail rules", () => {
  it("knows domains", () => {
    expect(domainProblem("example.net")).toBeNull();
    expect(domainProblem("sub.family.example")).toBeNull();
    expect(domainProblem("Example.net")).not.toBeNull();
    expect(domainProblem("localhost")).not.toBeNull();
    expect(domainProblem("a_b.net")).not.toBeNull();
    expect(domainProblem("x.123")).not.toBeNull();
  });
  it("knows addresses", () => {
    expect(addressProblem("alice@example.net")).toBeNull();
    expect(addressProblem("a.b+c@example.net")).toBeNull();
    expect(addressProblem("a..b@example.net")).not.toBeNull();
    expect(addressProblem("@example.net")).not.toBeNull();
    expect(addressProblem("alice")).not.toBeNull();
  });
  it("checks mailbox edits", () => {
    expect(mailboxProblems("alice@example.net", ["mom@example.net"], 1024)).toEqual([]);
    expect(mailboxProblems("alice@example.net", ["postmaster@example.net"], 0)).toHaveLength(1);
    expect(mailboxProblems("alice@example.net", ["alice@example.net"], 0)).toHaveLength(1);
    expect(mailboxProblems("alice@example.net", [], -1)).toHaveLength(1);
  });
  it("lists what's missing before turning it on", () => {
    const empty = settingsProblems({ enabled: true }, { domains: [], netbirdAddress: "", sesSecretSet: false, cloudflareTokenSet: false });
    expect(empty.length).toBeGreaterThan(4);
    const ready = settingsProblems(
      { enabled: true, pool: "tank", hostname: "mail.example.net", defaultDomain: "example.net", vpsPeer: "100.90.1.2", sesAccessKeyId: "AKIA", tlsMode: "self" },
      { domains: [{ name: "example.net" } as never], netbirdAddress: "100.90.1.7", sesSecretSet: true, cloudflareTokenSet: false },
    );
    expect(ready).toEqual([]);
  });
  it("matches records to checks", () => {
    expect(recordKey({ type: "MX", name: "example.net", value: "mail.example.net" })).toBe("MX example.net mail.example.net");
  });
});
