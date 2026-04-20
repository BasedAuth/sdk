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

    let token = TOKEN.lock().unwrap().clone().ok_or(AuthError::NotAuthenticated)?;
    let response =
        http::request::<ConstantResponse>("GET", crate::CONSTANT_URL, &[("X-Session-Token", &token)], None, Some(&[("key", key)]))?;

    response.value.ok_or(AuthError::InvalidResponse)
}
