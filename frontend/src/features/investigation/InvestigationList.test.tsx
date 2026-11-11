import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { InvestigationList } from "./InvestigationList";
import { example, jsonResponse } from "./testFixtures";

afterEach(() => vi.restoreAllMocks());

describe("InvestigationList", () => {
  it("lists saved investigations with links to reopen them", async () => {
    const history = example<{ items: { run: { id: string } }[] }>("history-response");
    vi.spyOn(globalThis, "fetch").mockResolvedValue(jsonResponse(history));
    render(<InvestigationList />);
    const links = await screen.findAllByRole("link");
    expect(links[0]).toHaveAttribute("href", `/investigations?run=${history.items[0].run.id}`);
  });
});
