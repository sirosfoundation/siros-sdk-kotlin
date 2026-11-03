//! UniFFI's binding generator, in library mode:
//!   cargo run --features bindgen --bin uniffi-bindgen -- generate --library <libnymauth_demo_issuer.so> --language kotlin --out-dir <dir>
fn main() {
  uniffi::uniffi_bindgen_main()
}
