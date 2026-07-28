import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  output: "standalone",
  // MIRAGE_E2E_FIXTURE's ephemeral dev server (playwright.config.ts) runs on
  // a different port but the same project directory as a developer's own
  // `npm run dev` — without a separate distDir, both `next dev` processes
  // read/write the same .next/ build cache concurrently and corrupt it
  // (observed: ENOENT on .next/server/app/**/route.js mid-session). Give it
  // its own build directory instead of assuming only one `next dev` is ever
  // running against this checkout at a time.
  distDir: process.env.MIRAGE_E2E_FIXTURE === "1" ? ".next-e2e-fixture" : ".next",
  experimental: {
    optimizePackageImports: ["three", "cytoscape"],
  },
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "X-Frame-Options", value: "DENY" },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "Referrer-Policy", value: "no-referrer" },
          {
            key: "Permissions-Policy",
            value: "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
          },
        ],
      },
    ];
  },
};

export default nextConfig;
