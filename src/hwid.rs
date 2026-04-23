// SPDX-FileCopyrightText: 2026 BasedAuth
// SPDX-License-Identifier: Apache-2.0

fn collect_cpuid() -> Vec<u8> {
    use std::arch::x86_64::__cpuid_count;

    let mut buf = Vec::with_capacity(128);

    let leaves: &[(u32, u32)] = &[
        (0x00000000, 0), // vendor string + max supported leaf
        (0x00000001, 0), // family, model, stepping + feature flags
        (0x00000004, 0), // cache topology: L1
        (0x00000004, 1), // cache topology: L2
        (0x00000004, 2), // cache topology: L3
        (0x80000002, 0), // brand string part 1
        (0x80000003, 0), // brand string part 2
        (0x80000004, 0)  // brand string part 3
    ];

    for &(leaf, sub) in leaves {
        let r = __cpuid_count(leaf, sub);
        buf.extend_from_slice(&r.eax.to_le_bytes());
        buf.extend_from_slice(&r.ebx.to_le_bytes());
        buf.extend_from_slice(&r.ecx.to_le_bytes());
        buf.extend_from_slice(&r.edx.to_le_bytes());
    }

    buf
}

pub(crate) fn get_hwid() -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&collect_cpuid());
    hasher.finalize().to_hex().to_string() // TODO: Add hard drives and PCiE devices
}
