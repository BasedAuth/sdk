// SPDX-FileCopyrightText: 2026 BasedAuth
// SPDX-License-Identifier: Apache-2.0

use crate::auth;
use crate::constant;
use crate::error::AuthError;
use std::ffi::{CStr, CString, c_char};
use std::sync::Mutex;

static LAST_ERROR: Mutex<Option<String>> = Mutex::new(None);

fn set_error(e: &AuthError) {
    *LAST_ERROR.lock().unwrap() = Some(e.to_string());
}

#[unsafe(no_mangle)]
pub extern "C" fn BA_Init(public_key_hex: *const c_char) -> bool {
    if public_key_hex.is_null() {
        set_error(&AuthError::InvalidKey);
        return false;
    }

    let key = unsafe { CStr::from_ptr(public_key_hex) }.to_string_lossy();

    auth::init(&key).map_or_else(|e| {
        set_error(&e);
        false
    }, |()| true)
}

#[unsafe(no_mangle)]
pub extern "C" fn BA_Authenticate(license_key: *const c_char) -> bool {
    if license_key.is_null() {
        set_error(&AuthError::InvalidKey);
        return false;
    }

    let key = unsafe { CStr::from_ptr(license_key) }.to_string_lossy();

    auth::authenticate(&key).map_or_else(|e| {
        set_error(&e);
        false
    }, |()| true)
}

#[unsafe(no_mangle)]
pub extern "C" fn BA_Refresh() -> bool {
    auth::refresh().map_or_else(|e| {
        set_error(&e);
        false
    }, |()| true)
}

#[unsafe(no_mangle)]
pub extern "C" fn BA_Constant(key: *const c_char) -> *const c_char {
    if key.is_null() {
        set_error(&AuthError::InvalidKey); // TODO: Replace with a new error type
        return std::ptr::null();
    }

    let key = unsafe { CStr::from_ptr(key) }.to_string_lossy();

    constant::constant(&key).map_or_else(|e| {
        set_error(&e);
        std::ptr::null()
    }, |v| CString::new(v).map_or(std::ptr::null(), |s| s.into_raw().cast_const()))
}

#[unsafe(no_mangle)]
pub extern "C" fn BA_GetError() -> *const c_char {
    LAST_ERROR
        .lock()
        .unwrap()
        .as_deref()
        .and_then(|msg| CString::new(msg).ok())
        .map_or(std::ptr::null(), |s| s.into_raw().cast_const())
}
