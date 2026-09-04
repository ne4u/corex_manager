// Bind the cdylib's internal symbol references to its own definitions at link
// time via -Bsymbolic. This prevents cross-.so symbol resolution when HAProxy
// dlopens multiple Rust cdylib modules with RTLD_GLOBAL via lua-load-per-thread.
//
// Without -Bsymbolic, thread 2's dlopen of haproxy_compression_module.so may
// resolve its mlua/haproxy-api/std references to thread 1's
// haproxy_req_fp_module.so symbols (exported globally via RTLD_GLOBAL),
// corrupting the Lua state and causing silent function registration failures.
// HAProxy 3.4+ rejects this with "Lua function 'X' is not referenced in all
// thread."
//
// -Bsymbolic only affects how the .so's own references are resolved (bound to
// its own definitions at link time). It does not change which symbols are
// exported in the dynamic symbol table, so Rust's own --version-script (which
// handles symbol visibility) is unaffected. Using a second --version-script
// would conflict with Rust's ("anonymous version tag cannot be combined with
// other version tags"), so -Bsymbolic is the correct approach.
fn main() {
    println!("cargo:rustc-link-arg-cdylib=-Wl,-Bsymbolic");
}
