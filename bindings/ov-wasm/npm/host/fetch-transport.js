// HTTP for the core over `fetch` (rust-core-tasks.md §2.2, host.rs `HttpTransport`).
//
// - never follows redirects (`redirect: "error"`, as the SDK), sends no cookies (`credentials:
//   "omit"`) and bypasses the HTTP cache (`cache: "no-store"`);
// - any status is a response; only failures without one reject, with a `TransportFailure`
//   `{ kind: "offline" | "timeout" | "tls" | "cancelled" | "other", message }`;
// - SSE (`openStream`) reads `response.body` chunk by chunk; the core parses the framing.
//   Browsers must not use EventSource (it can't send the bearer header).

const failure = (kind, message) => Object.assign(new Error(message), { name: "TransportFailure", kind });

function classify(e, timedOut) {
  if (timedOut) return failure("timeout", "the request timed out");
  if (e?.name === "AbortError") return failure("cancelled", "the request was cancelled");
  if (e?.name === "TimeoutError") return failure("timeout", "the request timed out");
  // fetch rejects with a TypeError for network failures (DNS, refused, offline, TLS, redirect).
  if (e instanceof TypeError) return failure("offline", e.message);
  return failure("other", String(e?.message ?? e));
}

/** @param {{ fetch?: typeof fetch, timeoutMs?: number }} [opts] */
export function fetchTransport(opts = {}) {
  const doFetch = opts.fetch ?? globalThis.fetch.bind(globalThis);

  async function start(req, stream) {
    const controller = new AbortController();
    let timedOut = false;
    const timer =
      opts.timeoutMs && !stream
        ? setTimeout(() => {
            timedOut = true;
            controller.abort();
          }, opts.timeoutMs)
        : undefined;
    try {
      const res = await doFetch(req.url, {
        method: req.method,
        headers: req.headers,
        body: req.body ?? undefined,
        redirect: "error",
        credentials: "omit",
        cache: "no-store",
        keepalive: !!req.keepalive,
        signal: controller.signal,
      });
      return { res, controller };
    } catch (e) {
      throw classify(e, timedOut);
    } finally {
      clearTimeout(timer);
    }
  }

  return {
    async send(req) {
      const { res } = await start(req, false);
      let body;
      try {
        body = new Uint8Array(await res.arrayBuffer());
      } catch (e) {
        throw classify(e, false);
      }
      return { status: res.status, headers: [...res.headers.entries()], body };
    },

    async openStream(req) {
      const { res, controller } = await start(req, true);
      const reader = res.body?.getReader();
      let closed = !reader;
      return {
        status: res.status,
        async nextChunk() {
          if (closed) return null;
          try {
            const { done, value } = await reader.read();
            if (done) {
              closed = true;
              return null;
            }
            return value;
          } catch (e) {
            if (closed) return null;
            throw classify(e, false);
          }
        },
        close() {
          closed = true;
          controller.abort();
        },
      };
    },
  };
}
