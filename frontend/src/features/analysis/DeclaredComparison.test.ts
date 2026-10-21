import { describe, expect, it } from "vitest";

import { compareDeclared } from "./DeclaredComparison";

describe("compareDeclared", () => {
  it("rolls sub-techniques up, splits matched / missed / extra and scores them", () => {
    const c = compareDeclared(["T1566.002", "T1059.001", "T1105", "T1999"], ["T1566", "T1059", "T1003"],
      new Set(["T1566", "T1059", "T1105", "T1003"]));
    expect(c.matched).toEqual(["T1059", "T1566"]);
    expect(c.missed).toEqual(["T1105"]);
    expect(c.missedOutsideModel).toEqual(["T1999"]);     // the model cannot predict it: not a miss
    expect(c.extra).toEqual(["T1003"]);
    expect(c.precision).toBeCloseTo(2 / 3);
    expect(c.recall).toBeCloseTo(2 / 3);
  });
});
