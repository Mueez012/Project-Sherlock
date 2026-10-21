import type { NextConfig } from "next";

// The browser only talks to this Next.js server; /api/* is proxied to the FastAPI
// backend, so there are no CORS problems and no backend URL inside components.
// Port 8001 because Splunk already uses 8000 on the development laptop.
const API_ORIGIN = process.env.API_ORIGIN ?? "http://127.0.0.1:8001";

const nextConfig: NextConfig = {
  reactStrictMode: true,
  devIndicators: false,   // no floating dev badge (it covered content in screenshots)
  experimental: {
    // Proxied request bodies are buffered up to this size (default 10 MB, which cut
    // uploads off). Slightly above the API's 20 MB limit so it can answer 413 itself.
    proxyClientMaxBodySize: "25mb",
  },
  async rewrites() {
    return [{ source: "/api/:path*", destination: `${API_ORIGIN}/api/:path*` }];
  },
};

export default nextConfig;
