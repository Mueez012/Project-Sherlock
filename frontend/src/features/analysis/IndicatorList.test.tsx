import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { IndicatorList } from "./IndicatorList";

describe("IndicatorList", () => {
  it("shows sentence numbers, or the table row for an indicator outside every sentence", () => {
    render(<IndicatorList indicators={[
      { type: "ipv4", value: "10.0.0.1", sentence_indices: [1, 4], context: ["The loader contacted 10.0.0.1."] },
      { type: "domain", value: "conlfex.com", sentence_indices: [],
        context: ["conlfex[.]com | Initial Compromise | Doppelganger domain for initial phishing | N/A | March 2022"] },
    ]} />);
    expect(screen.getByText("2, 5")).toBeInTheDocument();
    expect(screen.getByText(/conlfex\[\.\]com \| Initial Compromise/)).toBeInTheDocument();
  });
});
