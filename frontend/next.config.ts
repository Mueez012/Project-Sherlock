import type { NextConfig } from "next";

// The browser only talks to this Next.js server; /api/* is proxied to the hub (the FastAPI backend), so there
// are no CORS problems and no backend URL inside components.
//
// API_ORIGIN is read when the app is BUILT or `next dev` starts, because rewrites are fixed then:
//   local:   API_ORIGIN=http://127.0.0.1:8080 in frontend/.env.local (Splunk uses 8000 on the dev laptop)
//   Docker:  a build argument (http://app:8000 in docker-compose.yml)
const API_ORIGIN = process.env.API_ORIGIN ?? "http://127.0.0.1:8000";

const nextConfig: NextConfig = {
  output: "standalone",   // a self-contained server for the Docker image
  reactStrictMode: true,
  devIndicators: false,   // no floating dev badge (it covered content in screenshots)
  experimental: {
    // Real models can take minutes on a long report; the proxy's default timeout is 30 s.
    proxyTimeout: 600_000,
  },
  async rewrites() {
    return [{ source: "/api/:path*", destination: `${API_ORIGIN}/api/:path*` }];
  },
};

export default nextConfig;
