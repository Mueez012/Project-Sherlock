import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { percent } from "@/lib/confidence";

import { ConfidenceBadge } from "./ConfidenceBadge";

describe("ConfidenceBadge", () => {
  it.each([["high", 0.91], ["medium", 0.6], ["low", 0.35]] as const)("shows the number and the %s label, not colour alone", (band, value) => {
    render(<ConfidenceBadge value={value} band={band} />);
    const badge = screen.getByLabelText(new RegExp(`${band} confidence`, "i"));
    expect(badge).toHaveTextContent(percent(value));
    expect(badge).toHaveTextContent(new RegExp(band, "i"));
  });
  it("never rounds a probability below 1 up to 100%", () => {
    expect(percent(0.9994)).toBe("99%");
    expect(percent(0.35)).toBe("35%");
    expect(percent(1)).toBe("99%");             // float32 saturation is not certainty
    expect(percent(0.99999, 1)).toBe("99.9%");
  });
});
