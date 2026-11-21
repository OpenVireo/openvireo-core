#![no_main]
//! See `ov_fuzz::kdbx_inner`.

libfuzzer_sys::fuzz_target!(|data: &[u8]| ov_fuzz::kdbx_inner(data));
