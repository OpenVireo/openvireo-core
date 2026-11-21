#![no_main]
//! See `ov_fuzz::share_link`.

libfuzzer_sys::fuzz_target!(|data: &[u8]| ov_fuzz::share_link(data));
