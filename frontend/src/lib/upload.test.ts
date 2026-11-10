import { describe, expect, it } from "vitest";

import { validateUpload } from "./upload";

const file = (name: string, size: number) => new File([new Uint8Array(size)], name);

describe("validateUpload", () => {
  it("accepts a supported file with a name", () => {
    expect(validateUpload({ file: file("r.pdf", 10), incidentName: "Op" })).toEqual({});
  });
  it("rejects unsupported types", () => {
    expect(validateUpload({ file: file("evil.exe", 10), incidentName: "Op" }).file).toMatch(/not supported/);
  });
  it("rejects files over 20 MB and empty files", () => {
    expect(validateUpload({ file: file("big.txt", 21 * 1024 * 1024), incidentName: "Op" }).file).toMatch(/limit is 20 MB/);
    expect(validateUpload({ file: file("e.txt", 0), incidentName: "Op" }).file).toMatch(/empty/);
  });
  it("requires an incident name and a file", () => {
    const errors = validateUpload({ file: null, incidentName: "   " });
    expect(errors.incidentName).toBeDefined();
    expect(errors.file).toBeDefined();
  });
});
