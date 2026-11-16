// Host adapters for @openvireo/core-wasm (rust-core-tasks.md §2.2): pass them in the `Host`
// object to `new core.OvClient(config, host)`.
export { fetchTransport } from "./fetch-transport.js";
export { indexedDbCache } from "./indexeddb-cache.js";
export { memoryCache, memoryStore } from "./memory.js";

/** `Date.now()`. */
export const systemClock = { nowUnixMs: () => Date.now() };

const LEVELS = ["error", "warn", "info", "debug", "trace"];

/** Logs to `console` at `minLevel` and above (default `"info"`). The core never logs secrets. */
export function consoleLog(minLevel = "info") {
  const max = LEVELS.indexOf(minLevel);
  return {
    log(level, target, msg) {
      if (LEVELS.indexOf(level) > max) return;
      const fn = level === "error" ? console.error : level === "warn" ? console.warn : level === "info" ? console.info : console.debug;
      fn(`[${target}] ${msg}`);
    },
  };
}
