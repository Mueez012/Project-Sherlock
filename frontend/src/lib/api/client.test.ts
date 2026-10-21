import { describe, expect, it } from "vitest";

import { ERROR_MESSAGES, parseProblem } from "./client";

// Every code the backend can send (ttp_api/routes/analyses.py, errors.py, schemas.ErrorCode).
const API_CODES = ["file_too_large", "unsupported_file", "empty_file", "empty_text", "text_too_long",
  "bad_options", "queue_full", "model_loading", "model_unavailable", "not_found", "not_finished",
  "job_failed", "no_text_layer", "no_text", "too_many_sentences", "model_error", "timeout"];

describe("API errors", () => {
  it.each(API_CODES)("has a readable message for %s", (code) => {
    const err = parseProblem(400, { code, detail: "raw detail", status: 400 });
    expect(err.code).toBe(code);
    expect(err.message).toBe(ERROR_MESSAGES[code]);
    expect(err.message).not.toBe("raw detail");
  });
  it("falls back to the server detail for unknown codes", () => {
    expect(parseProblem(500, { code: "weird", detail: "something broke" }).message).toBe("something broke");
  });
  it("survives a non-JSON body", () => {
    expect(parseProblem(502, null).code).toBe("http_502");
  });
});
