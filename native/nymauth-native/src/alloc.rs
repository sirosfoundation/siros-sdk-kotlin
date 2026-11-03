//! The library's global allocator: the system allocator, counting what it hands out for
//! nym-longfellow's `measure` module, as community-demo's addons do (`native/*/node/src/alloc.rs`).
//! The scope of `heap_mb` and `witness_mb` is every Rust allocation in this library, on any thread,
//! while the step runs. Kotlin and Swift allocate outside it.

use std::alloc::{GlobalAlloc, Layout, System};

#[inline]
fn grew(n: usize) {
  #[cfg(feature = "longfellow")]
  nym_longfellow::measure::heap_grew(n);
  let _ = n;
}

#[inline]
fn shrank(n: usize) {
  #[cfg(feature = "longfellow")]
  nym_longfellow::measure::heap_shrank(n);
  let _ = n;
}

struct Counting;

// SAFETY: every call is forwarded to the system allocator unchanged; only the sizes are counted.
unsafe impl GlobalAlloc for Counting {
  unsafe fn alloc(&self, l: Layout) -> *mut u8 {
    let p = unsafe { System.alloc(l) };
    if !p.is_null() {
      grew(l.size());
    }
    p
  }

  unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
    let p = unsafe { System.alloc_zeroed(l) };
    if !p.is_null() {
      grew(l.size());
    }
    p
  }

  unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
    unsafe { System.dealloc(p, l) };
    shrank(l.size());
  }

  unsafe fn realloc(&self, p: *mut u8, l: Layout, new_size: usize) -> *mut u8 {
    let q = unsafe { System.realloc(p, l, new_size) };
    if !q.is_null() {
      if new_size > l.size() {
        grew(new_size - l.size());
      } else {
        shrank(l.size() - new_size);
      }
    }
    q
  }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;
