import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/**/*.test.js"],
    // Each file gets its own module graph, so each loads its own core instance.
    isolate: true,
  },
});
