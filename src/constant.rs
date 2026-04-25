// SPDX-FileCopyrightText: 2026 BasedAuth
// SPDX-License-Identifier: Apache-2.0

use crate::error::AuthError;
use crate::http;
use crate::state::{PUBLIC_KEY, TOKEN};
use serde::Deserialize;

#[derive(Deserialize)]
struct ConstantResponse {
    value: Option<String>
}

pub fn constant(key: &str) -> Result<String, AuthError> {
    if PUBLIC_KEY.get().is_none() {
        return Err(AuthError::Uninitialized);
    }

    if TOKEN.lock().unwrap().is_none() {
        return Err(AuthError::NotAuthenticated);
    }

    let response = http::request::<ConstantResponse>("GET", crate::CONSTANT_URL, None, Some(&[("key", key)]))?;
    response.value.ok_or(AuthError::InvalidResponse)
}
