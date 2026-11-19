// The core's one error type, shared by every entry point of the package (index, sync, lite, lite-sync).

/** The one error type of the core. `code` is the stable wire string (`"plan_limit"`, `"internal"`, …). */
export class OvError extends Error {
  constructor(code, message, opts = {}) {
    super(message, opts.cause === undefined ? undefined : { cause: opts.cause });
    this.name = "OvError";
    this.code = code;
    if (opts.status !== undefined) this.status = opts.status;
    if (opts.retryAfter !== undefined) this.retryAfter = opts.retryAfter;
    if (opts.details !== undefined) this.details = opts.details;
    if (opts.serverCode !== undefined) this.serverCode = opts.serverCode;
  }

  /** Whether the server couldn't be reached (network error or 502/503/504), as the SDK's `isUnreachable`. */
  get isUnreachable() {
    return this.code === "network_error" || this.status === 502 || this.status === 503 || this.status === 504;
  }
}
