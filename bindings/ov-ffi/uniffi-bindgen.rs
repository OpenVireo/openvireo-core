//! `uniffi-bindgen` for this crate (built with `--features cli`), so the generator always matches
//! the pinned `uniffi` version. `cargo xtask xcframework` runs it.

fn main() {
    uniffi::uniffi_bindgen_main()
}
