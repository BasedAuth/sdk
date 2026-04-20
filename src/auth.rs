// SPDX-FileCopyrightText: 2026 BasedAuth
// SPDX-License-Identifier: Apache-2.0

use crate::error::AuthError;
use crate::http;
use crate::hwid;
use crate::state::{EXPIRES_AT, PUBLIC_KEY, TOKEN};
use serde::Deserialize;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Deserialize)]
struct AuthResponse {
    message: Option<String>,
    token: Option<String>,
    expires_at: Option<u64>
}

pub fn init(public_key_hex: &str) -> Result<(), AuthError> {
    hex::decode(public_key_hex).map_err(|_| AuthError::InvalidKey)?;
    PUBLIC_KEY.set(public_key_hex.to_owned()).map_err(|_| AuthError::AlreadyInitialized)?;
    Ok(())
}

pub fn authenticate(license_key: &str) -> Result<(), AuthError> {
    if PUBLIC_KEY.get().is_none() {
        return Err(AuthError::Uninitialized);
    }

    let response = http::request::<AuthResponse>(
        "POST",
        crate::AUTH_URL,
        &[("X-Hardware-ID", &hwid::get_hwid())],
        Some(&serde_json::json!({ "license_key": license_key })),
        None
    )?;

    if let Some(msg) = response.message {
        match msg.as_str() {
            "Application is currently disabled" => return Err(AuthError::ApplicationDisabled),
            "Hardware ID mismatch" => return Err(AuthError::HwidMismatch),
            "Invalid hardware ID" => return Err(AuthError::InvalidHwid),
            "Invalid license key" => return Err(AuthError::InvalidKey),
            "License has expired" => return Err(AuthError::KeyExpired),
            _ => return Err(AuthError::InvalidResponse)
        }
    }

    let token = response.token.ok_or(AuthError::InvalidResponse)?;
    let expires_at = response.expires_at.ok_or(AuthError::InvalidResponse)?;

    if token.len() != 64 || hex::decode(&token).is_err() {
        return Err(AuthError::InvalidResponse);
    }

    if expires_at < SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() {
        return Err(AuthError::InvalidKey);
    }

    *TOKEN.lock().unwrap() = Some(token);
    *EXPIRES_AT.lock().unwrap() = Some(expires_at);

    Ok(())
}

pub fn refresh() -> Result<(), AuthError> {
    if PUBLIC_KEY.get().is_none() {
        return Err(AuthError::Uninitialized);
    }

    let token = TOKEN.lock().unwrap().clone().ok_or(AuthError::Uninitialized)?;

    let response = http::request::<AuthResponse>(
        "POST",
        crate::REFRESH_URL,
        &[("X-Session-Token", &token)],
        None,
        None
    )?;

    let token = response.token.ok_or(AuthError::InvalidResponse)?;
    let expires_at = response.expires_at.ok_or(AuthError::InvalidResponse)?;

    if token.len() != 64 || hex::decode(&token).is_err() {
        return Err(AuthError::InvalidResponse);
    }

    *TOKEN.lock().unwrap() = Some(token);
    *EXPIRES_AT.lock().unwrap() = Some(expires_at);

    Ok(())
}
