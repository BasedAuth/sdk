// SPDX-FileCopyrightText: 2026 BasedAuth
// SPDX-License-Identifier: Apache-2.0

pub(crate) fn get_hwid() -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update("stub".as_bytes());
    hasher.finalize().to_hex().to_string() // TODO: Real HWID implementation
}
