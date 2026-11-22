import { readFileSync } from "node:fs";
import pkg from "../pkg/package.json" with { type: "json" };

export const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
export const bytes = (s) => new TextEncoder().encode(s);
export const text = (b) => new TextDecoder().decode(b);
export const fromHex = (h) => new Uint8Array((h.match(/../g) ?? []).map((x) => parseInt(x, 16)));
export const b64u = (b) => Buffer.from(b).toString("base64url");
export const fromB64u = (s) => new Uint8Array(Buffer.from(s, "base64url"));
// FIPS 180-2 "abc".
export const SHA256_ABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

const vectorsDir = new URL("../../../vectors/", import.meta.url);
/** vectors/test-vectors.json (SPEC test vectors). */
export const vectors = () => JSON.parse(readFileSync(new URL("test-vectors.json", vectorsDir), "utf8"));
/** vectors/opaque-transcripts.json. */
export const opaqueTranscripts = () => JSON.parse(readFileSync(new URL("opaque-transcripts.json", vectorsDir), "utf8"));
/** A file under vectors/. */
export const vectorFile = (path) => new Uint8Array(readFileSync(new URL(path, vectorsDir)));

/** The thrown error of `fn` (sync or async). */
export async function errorOf(fn) {
  try {
    await fn();
  } catch (e) {
    return e;
  }
  throw new Error("expected an error");
}

// The version the package was built with (xtask fills it in from the workspace version).
export const PKG_VERSION = pkg.version;
