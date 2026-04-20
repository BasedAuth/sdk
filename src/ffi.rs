// SPDX-FileCopyrightText: 2026 BasedAuth
// SPDX-License-Identifier: Apache-2.0

use crate::auth;
use crate::error::AuthError;
use std::ffi::{CStr, CString, c_char};
use std::sync::Mutex;

static LAST_ERROR: Mutex<Option<String>> = Mutex::new(None);

fn set_error(e: AuthError) {
    *LAST_ERROR.lock().unwrap() = Some(e.to_string());
}

#[unsafe(no_mangle)]
pub extern "C" fn BA_Init(public_key_hex: *const c_char) -> bool {
    if public_key_hex.is_null() {
        set_error(AuthError::InvalidKey);
        return false;
    }

    let key = unsafe { CStr::from_ptr(public_key_hex) }.to_string_lossy();

    auth::init(&key).map(|_| true).unwrap_or_else(|e| {
        set_error(e);
        false
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn BA_Authenticate(license_key: *const c_char) -> bool {
    if license_key.is_null() {
        set_error(AuthError::InvalidKey);
        return false;
    }

    let key = unsafe { CStr::from_ptr(license_key) }.to_string_lossy();

    auth::authenticate(&key).map(|_| true).unwrap_or_else(|e| {
        set_error(e);
        false
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn BA_GetError() -> *const c_char {
    LAST_ERROR
        .lock()
        .unwrap()
        .as_deref()
        .and_then(|msg| CString::new(msg).ok())
        .map(|s| s.into_raw() as *const _)
        .unwrap_or(std::ptr::null())
}
