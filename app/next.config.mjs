import { createRequire } from "module";
const require = createRequire(import.meta.url);

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // NOTE: `@solana/web3.js` is intentionally NOT transpiled. It ships its own
  // CJS + ESM + browser builds, and putting it in `transpilePackages` makes Next 14
  // emit a broken server `vendor-chunks/@solana.js` reference (500 on `next start`).
  transpilePackages: ["@lightprotocol/stateless.js", "@coral-xyz/anchor"],
  webpack: (config, { isServer }) => {
    if (!isServer) {
      config.resolve.fallback = {
        ...(config.resolve.fallback || {}),
        fs: false,
        net: false,
        tls: false,
        child_process: false,
        buffer: require.resolve("buffer/"),
        process: require.resolve("process/browser"),
      };
    }
    return config;
  },
};

export default nextConfig;
