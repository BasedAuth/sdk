// SPDX-FileCopyrightText: 2026 BasedAuth
// SPDX-License-Identifier: Apache-2.0

fn collect_cpuid() -> Vec<u8> {
    use std::arch::x86_64::__cpuid_count;

    let mut buf = Vec::with_capacity(128);

    let leaves: &[(u32, u32)] = &[
        (0x00000000, 0), // vendor string + max supported leaf
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

#[cfg(unix)]
fn collect_gpu() -> Vec<u8> {
    let mut entries: Vec<String> = Vec::new();

    if let Ok(dir) = std::fs::read_dir("/sys/bus/pci/devices") {
        for entry in dir.flatten() {
            let path = entry.path();

            let read = |attr: &str| std::fs::read_to_string(path.join(attr)).unwrap_or_default().trim().to_owned();

            if read("class").starts_with("0x03") {
                // Display Controller
                entries.push(format!("{}|{}", read("vendor"), read("device")));
            }
        }
    }

    entries.sort_unstable();
    entries.join("\n").into_bytes()
}

#[cfg(windows)]
fn collect_gpu() -> Vec<u8> {
    use windows::Win32::Graphics::Dxgi::*;

    let mut entries: Vec<String> = Vec::new();

    unsafe {
        let factory: IDXGIFactory = CreateDXGIFactory().unwrap();
        let mut i = 0;
        while let Ok(adapter) = factory.EnumAdapters(i) {
            let desc = adapter.GetDesc().unwrap();
            entries.push(format!("{:#06x}|{:#06x}", desc.VendorId, desc.DeviceId));
            i += 1;
        }
    }

    entries.sort_unstable();
    entries.join("\n").into_bytes()
}

pub(crate) fn get_hwid() -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&collect_cpuid());
    hasher.update(&collect_gpu());
    hasher.finalize().to_hex().to_string() // TODO: Add hard drives
}
