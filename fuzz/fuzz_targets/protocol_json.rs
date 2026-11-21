#![no_main]
//! See `ov_fuzz::protocol_json`.

libfuzzer_sys::fuzz_target!(|data: &[u8]| ov_fuzz::protocol_json(data));
