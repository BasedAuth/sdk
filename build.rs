// SPDX-FileCopyrightText: 2026 BasedAuth
// SPDX-License-Identifier: Apache-2.0

fn main() {
    cbindgen::Builder::new()
        .with_crate(std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .with_language(cbindgen::Language::C)
        .with_cpp_compat(true)
        .with_documentation(true)
        .with_pragma_once(true)
        .with_header("/* SPDX-FileCopyrightText: 2026 BasedAuth\n   SPDX-License-Identifier: Apache-2.0 */")
        .generate()
        .unwrap()
        .write_to_file("include/basedauth.h");
}
