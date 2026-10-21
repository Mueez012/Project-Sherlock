import { defineConfig, devices } from "@playwright/test";

// Uses the dev server on :3000 (started automatically if it is not running).
// Mocked specs need no backend; the @real spec needs the FastAPI server on :8001.
export default defineConfig({
  testDir: "tests/e2e",
  timeout: 60_000,
  expect: { timeout: 10_000 },
  workers: 2,
  reporter: [["list"]],
  use: { baseURL: "http://localhost:3000", trace: "retain-on-failure" },
  webServer: { command: "npm run dev", url: "http://localhost:3000", reuseExistingServer: true, timeout: 120_000 },
  projects: [
    { name: "desktop-dark", use: { viewport: { width: 1440, height: 900 }, colorScheme: "dark" } },
    { name: "mobile-light", use: { ...devices["Pixel 7"], viewport: { width: 390, height: 844 }, colorScheme: "light" } },
  ],
});
