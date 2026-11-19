// @vitest-environment node
// The lite module's panic guard (its own file: a panic poisons the instance for the rest of the file).
import { expect, it } from "vitest";
import { OvError } from "../pkg/lite.js";
import { loadLiteSync } from "../pkg/lite-sync.js";

it("a panic in the lite module becomes OvError(internal) and poisons the instance", () => {
  const lite = loadLiteSync();
  const hooks = lite[Symbol.for("@openvireo/core-wasm/test-hooks")];
  let err;
  try {
    hooks.__testPanic("boom");
  } catch (e) {
    err = e;
  }
  expect(err).toBeInstanceOf(OvError);
  expect([err.code, err.message]).toEqual(["internal", expect.stringMatching(/the core panicked: boom/)]);
  expect(lite.poisoned).toBe(true);
  expect(() => lite.sha256(new Uint8Array())).toThrow(/unusable after an earlier panic/);
});
