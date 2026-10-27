import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { linkTarget } from "../links";
import { foldSeries, formatUnit, TimeChart } from "./TimeChart";

afterEach(cleanup);

describe("TimeChart", () => {
  it("draws lines with gaps, a legend for several series and a table view", () => {
    const { container } = render(
      <TimeChart
        from="2026-10-27T00:00:00Z"
        step={60}
        unit="bytes/s"
        label="Network"
        series={[
          { key: "rx", label: "Download", values: [1, 2, null, 4, 5] },
          { key: "tx", label: "Upload", values: [5, 4, 3, 2, 1] },
        ]}
      />,
    );
    const paths = [...container.querySelectorAll("path")].map((p) => p.getAttribute("d") ?? "");
    // The gap starts a new segment (two M commands for Download).
    expect(paths[0]!.match(/M/g)?.length).toBe(2);
    expect(screen.getByText("Download")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Table" }));
    expect(screen.getAllByRole("row").length).toBe(6);
    expect(screen.getAllByText("–").length).toBe(1);
  });

  it("says when there's nothing to show", () => {
    render(<TimeChart from="2026-10-27T00:00:00Z" step={10} unit="percent" label="CPU" series={[{ key: "c", label: "CPU", values: [null, null] }]} />);
    expect(screen.getByText("No data for this range yet.")).toBeTruthy();
  });

  it("folds many series into Other and formats units", () => {
    const many = Array.from({ length: 11 }, (_, i) => ({ key: `s${i}`, label: `S${i}`, values: [i, i] }));
    const f = foldSeries(many);
    expect(f.length).toBe(8);
    expect(f.at(-1)!.label).toBe("Other (4)");
    expect(f.at(-1)!.values).toEqual([0 + 1 + 2 + 3, 0 + 1 + 2 + 3]);
    expect(formatUnit(45.2, "celsius")).toBe("45 °C");
    expect(formatUnit(12.34, "percent")).toBe("12%");
  });
});

describe("links", () => {
  it("maps alert links to apps", () => {
    expect(linkTarget("storage/pool/tank")).toEqual({ app: "os.hardy.storage", args: { pool: "tank" } });
    expect(linkTarget("storage/disks/sda")).toEqual({ app: "os.hardy.storage", args: { section: "disks", disk: "sda" } });
    expect(linkTarget("ups")).toEqual({ app: "os.hardy.control", args: { section: "ups" } });
    expect(linkTarget("control/notifications")).toEqual({ app: "os.hardy.control", args: { section: "notifications" } });
    expect(linkTarget("somewhere/else")).toBeNull();
  });
});
