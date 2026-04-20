// SPDX-FileCopyrightText: 2026 BasedAuth
// SPDX-License-Identifier: Apache-2.0

use std::sync::{Mutex, OnceLock};

pub static PUBLIC_KEY: OnceLock<String> = OnceLock::new();
pub static TOKEN: Mutex<Option<String>> = Mutex::new(None);
pub static EXPIRES_AT: Mutex<Option<u64>> = Mutex::new(None);
