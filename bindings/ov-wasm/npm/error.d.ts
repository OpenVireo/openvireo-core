export interface OvErrorOptions {
  status?: number;
  retryAfter?: number;
  details?: Record<string, unknown> | string;
  serverCode?: string;
  cause?: unknown;
}

/** The one error type of the core. `code` is the stable wire string (`"plan_limit"`, `"internal"`, …). */
export class OvError extends Error {
  constructor(code: string, message: string, opts?: OvErrorOptions);
  readonly name: "OvError";
  /** The wire code: an `OvErrorCode` string, or an untyped server code. */
  code: string;
  status?: number;
  retryAfter?: number;
  /** The SDK's camelCase details object. */
  details?: Record<string, unknown> | string;
  /** A server code the core has no variant for (then `code` holds it too). */
  serverCode?: string;
  /** Network error or 502/503/504 (the SDK's `isUnreachable`). */
  readonly isUnreachable: boolean;
}
