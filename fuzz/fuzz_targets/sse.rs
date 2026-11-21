#![no_main]
//! See `ov_fuzz::sse`.

libfuzzer_sys::fuzz_target!(|data: &[u8]| ov_fuzz::sse(data));
