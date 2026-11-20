/** @type {import('next').NextConfig} */
const nextConfig = {
  // Static export: the build produces plain files in out/. No server, no API routes, nothing that can receive code.
  output: "export",
  trailingSlash: true,
  images: { unoptimized: true },
  poweredByHeader: false,
};

export default nextConfig;
