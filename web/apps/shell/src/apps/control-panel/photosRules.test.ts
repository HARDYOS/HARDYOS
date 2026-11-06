import type { PhotosSettings } from "@hardy/api-client";
import { describe, expect, it } from "vitest";
import { libraryProblems, mlLabel } from "./photosRules";

const base: PhotosSettings = {
  sso: true,
  passwordLogin: false,
  autoLaunch: false,
  defaultQuotaGiB: 0,
  mlAcceleration: "auto",
  scanHours: 6,
  watch: false,
  libraries: [],
  family: { enabled: false, name: "Family Photos", members: [] },
};

describe("photos rules", () => {
  it("accepts good libraries", () => {
    expect(libraryProblems({ ...base, libraries: [{ ownerId: 2, share: "EXISTING", path: "Pictures/2019", name: "Old" }] })).toEqual([]);
    expect(libraryProblems({ ...base, libraries: [{ ownerId: 2, share: "EXISTING", path: "", name: "All" }] })).toEqual([]);
  });

  it("catches what the server would refuse", () => {
    const p = libraryProblems({
      ...base,
      scanHours: 0,
      libraries: [
        { ownerId: 0, share: "EXISTING", path: "../etc", name: "" },
        { ownerId: 2, share: "EXISTING", path: "a", name: "x" },
        { ownerId: 2, share: "EXISTING", path: "a/", name: "y" },
      ],
    });
    expect(p.some((x) => x.includes("whose library"))).toBe(true);
    expect(p.some((x) => x.includes("give it a name"))).toBe(true);
    expect(p.some((x) => x.includes("inside the shared folder"))).toBe(true);
    expect(p.some((x) => x.includes("already in that person's library"))).toBe(true);
    expect(p.some((x) => x.includes("1 to 168"))).toBe(true);
  });

  it("names machine learning in plain words", () => {
    expect(mlLabel("cuda")).toBe("NVIDIA GPU");
    expect(mlLabel("cpu")).toBe("Processor");
  });
});
