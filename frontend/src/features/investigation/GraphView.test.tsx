import { act, fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { Snapshot } from "@/lib/api/investigations";

import { GraphView } from "./GraphView";
import { example } from "./testFixtures";

const { graph } = example<Snapshot>("snapshot-response");
const position = (name: RegExp) => screen.getByRole("button", { name }).getAttribute("transform");
const NODE = /example\.com, from the report/i;

describe("GraphView", () => {
  it("draws nodes at one size whatever the zoom, and zooms the distances", async () => {
    const user = userEvent.setup();
    render(<GraphView graph={graph} selectedId={null} onSelect={vi.fn()} fresh={new Set()} />);
    const radius = () => screen.getByRole("button", { name: NODE }).querySelector("circle")?.getAttribute("r");
    const fitted = position(NODE);
    expect(radius()).toBe("8");
    await user.click(screen.getByRole("button", { name: "Zoom in" }));
    expect(position(NODE)).not.toBe(fitted);
    expect(radius()).toBe("8");
    await user.click(screen.getByRole("button", { name: "Fit the whole graph" }));
    expect(position(NODE)).toBe(fitted);
  });

  it("pans when the background is dragged", () => {
    render(<GraphView graph={graph} selectedId={null} onSelect={vi.fn()} fresh={new Set()} />);
    const before = position(NODE);
    const background = document.querySelector(".graph-pan") as SVGRectElement;
    background.setPointerCapture = vi.fn();
    fireEvent.pointerDown(background, { clientX: 100, clientY: 100, pointerId: 1 });
    fireEvent.pointerMove(background, { clientX: 160, clientY: 130, pointerId: 1 });
    fireEvent.pointerUp(background, { pointerId: 1 });
    expect(position(NODE)).not.toBe(before);
  });

  it("zooms with the mouse wheel without scrolling the page", () => {
    render(<GraphView graph={graph} selectedId={null} onSelect={vi.fn()} fresh={new Set()} />);
    const before = position(NODE);
    const wheel = new WheelEvent("wheel", { deltaY: -300, clientX: 50, clientY: 50, cancelable: true });
    act(() => { screen.getByRole("group", { name: /indicator graph/i }).dispatchEvent(wheel); });
    expect(wheel.defaultPrevented).toBe(true);
    expect(position(NODE)).not.toBe(before);
  });

  it("selects a node with the keyboard", async () => {
    const onSelect = vi.fn();
    const user = userEvent.setup();
    render(<GraphView graph={graph} selectedId={null} onSelect={onSelect} fresh={new Set()} />);
    screen.getByRole("button", { name: NODE }).focus();
    await user.keyboard("{Enter}");
    expect(onSelect).toHaveBeenCalledWith(expect.objectContaining({ value: "example.com" }));
  });
});
