//! Wiping freed memory in the module (shared with `bindings/ov-wasm-lite`).
//!
//! wasm-bindgen copies every `&[u8]`/`&str` argument into linear memory and frees the copy unzeroed
//! after the call, and the domain crates leave their own temporaries (Argon2's memory blocks, serde
//! buffers, intermediate keys) in freed heap blocks and in the dead part of the shadow stack. The
//! exports already wrap the secrets they own in `Zeroizing`; these two measures cover the rest:
//!
//! - [`ZeroOnFree`], the module's global allocator on wasm32: every heap block is zeroed when it is
//!   freed (`memory.fill`, then a `black_box` so the stores aren't elided), so no freed block keeps
//!   a password, key or plaintext. Reallocation goes through alloc + copy + free, so the old block
//!   is wiped too.
//! - [`scrub_stack`] (`__scrubStack`): the loaders call it after every call into the module returns
//!   (and when an async call settles), zeroing the 64 KiB of shadow stack below the current frame.
//!
//! Zeroing costs a memset per free: about 10–20 ms for an Argon2 run at the SPEC's 64 MiB, small
//! next to the Argon2 work itself.

use std::alloc::{GlobalAlloc, Layout, System};

/// The system allocator, zeroing every block it frees.
pub struct ZeroOnFree;

// SAFETY: forwards to `System`; the only addition writes zeroes over a block the caller owns and is
// about to free, within its layout.
unsafe impl GlobalAlloc for ZeroOnFree {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller upholds `GlobalAlloc::alloc`'s contract.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: as above.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` was allocated by this allocator with `layout`, so `layout.size()` bytes are
        // ours to write until we free them.
        unsafe {
            std::ptr::write_bytes(ptr, 0, layout.size());
            std::hint::black_box(ptr);
            System.dealloc(ptr, layout);
        }
    }
}

#[cfg(target_arch = "wasm32")]
#[global_allocator]
static ALLOCATOR: ZeroOnFree = ZeroOnFree;

/// Bytes of dead shadow stack [`scrub_stack`] zeroes.
const SCRUB_BYTES: usize = 64 * 1024;

/// Zeroes the shadow stack below the caller (where the frames of the call that just returned were).
/// Hidden from the loaded API; the loaders call it.
#[doc(hidden)]
#[wasm_bindgen::prelude::wasm_bindgen(js_name = "__scrubStack")]
#[inline(never)]
pub fn scrub_stack() {
    let mut buf = [0u8; SCRUB_BYTES];
    std::hint::black_box(&mut buf);
}
