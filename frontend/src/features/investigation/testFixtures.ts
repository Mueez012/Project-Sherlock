// Test fixtures: IOC Hunter's own captured answers (services/ioc/docs/api/examples), so tests use the real shapes.
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";

/** services/ioc/docs/api/examples, found by walking up from the working directory (frontend/ or the repo root). */
function examplesDir(): string {
  for (let dir = process.cwd(); ; dir = dirname(dir)) {
    const candidate = join(dir, "services", "ioc", "docs", "api", "examples");
    if (existsSync(candidate)) return candidate;
    if (dirname(dir) === dir) throw new Error("services/ioc/docs/api/examples not found");
  }
}

const EXAMPLES = examplesDir();

export function example<T = Record<string, unknown>>(name: string): T {
  return JSON.parse(readFileSync(join(EXAMPLES, `${name}.json`), "utf8")) as T;
}

export function jsonResponse(body: unknown, status = 200, headers: Record<string, string> = {}) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...headers } });
}

type Route = (url: string, init?: RequestInit) => Response | Promise<Response> | undefined;

/** A fetch stand-in that answers by URL and method; records every call. */
export function routedFetch(route: Route) {
  const calls: { url: string; init?: RequestInit }[] = [];
  const fn = async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    calls.push({ url, init });
    const answer = await route(url, init);
    if (!answer) throw new Error(`unexpected request ${init?.method ?? "GET"} ${url}`);
    return answer;
  };
  return { fn, calls };
}
