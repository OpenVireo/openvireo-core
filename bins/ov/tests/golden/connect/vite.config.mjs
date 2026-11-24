// vite-node config for record.ts: run from the root of an openvireo-sdk checkout (see README.md).
// Plain object (no `vitest/config` import) so it loads from outside the SDK tree.
import { resolve } from "node:path";

const sdk = process.env.OPENVIREO_SDK ?? process.cwd();
const p = (rel) => resolve(sdk, "packages", rel);

export default {
  resolve: {
    alias: [
      { find: /^@openvireo\/sdk$/, replacement: p("sdk/src/index.ts") },
      { find: /^@openvireo\/sdk\/storage\/node$/, replacement: p("sdk/src/auth/storage-node.ts") },
      { find: /^@sdk-test\/(.*)$/, replacement: p("sdk/test/helpers/$1") },
      { find: /^@sdk-src\/(.*)$/, replacement: p("sdk/src/$1") },
      { find: /^@connect\/(.*)$/, replacement: p("connect/src/$1") },
    ],
  },
  server: { fs: { strict: false } },
};
