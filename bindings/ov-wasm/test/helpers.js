export const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
export const bytes = (s) => new TextEncoder().encode(s);
export const fromHex = (h) => new Uint8Array(h.match(/../g).map((x) => parseInt(x, 16)));
// FIPS 180-2 "abc".
export const SHA256_ABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
