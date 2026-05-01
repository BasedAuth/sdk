// SPDX-FileCopyrightText: 2026 BasedAuth
// SPDX-License-Identifier: Apache-2.0

use crate::error::AuthError;
use crate::hwid;
use crate::state::{PUBLIC_KEY, TOKEN};
use serde::de::DeserializeOwned;
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

static CLIENT: OnceLock<reqwest::blocking::Client> = OnceLock::new();

pub(crate) fn request<T: DeserializeOwned>(
    method: &str, url: &str, json: Option<&serde_json::Value>, query: Option<&[(&str, &str)]>
) -> Result<T, AuthError> {
    let public_key_hex = PUBLIC_KEY.get().ok_or(AuthError::Uninitialized)?;
    let client = CLIENT.get_or_init(|| {
        reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent(concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION")))
            .build()
            .unwrap()
    });

    let mut req = if method == "POST" {
        client.post(url)
    } else {
        client.get(url)
    }
    .header("X-Hardware-ID", hwid::get_hwid());

    if let Some(token) = TOKEN.lock().unwrap().as_deref() {
        req = req.header("X-Session-Token", token);
    }

    if let Some(json) = json {
        req = req.json(json);
    }

    if let Some(query) = query {
        req = req.query(query);
    }

    let res = req.send().map_err(|_| AuthError::ServiceUnavailable)?;

    let signature =
        res.headers().get("x-signature").and_then(|v| v.to_str().ok()).map(ToOwned::to_owned).ok_or(AuthError::InvalidSignature)?;

    let timestamp =
        res.headers().get("x-timestamp").and_then(|v| v.to_str().ok()).map(ToOwned::to_owned).ok_or(AuthError::InvalidSignature)?;

    let body = res.text().map_err(|_| AuthError::ServiceUnavailable)?;

    let key_bytes = hex::decode(public_key_hex).map_err(|_| AuthError::InvalidSignature)?;
    let sig_bytes = hex::decode(&signature).map_err(|_| AuthError::InvalidSignature)?;

    let public_key = dryoc::sign::PublicKey::try_from(key_bytes.as_slice()).map_err(|_| AuthError::InvalidSignature)?;

    let message = format!("{timestamp}{body}");
    let mut combined = sig_bytes;
    combined.extend_from_slice(message.as_bytes());

    let signed_message = dryoc::sign::SignedMessage::<dryoc::types::StackByteArray<64>, Vec<u8>>::from_bytes(&combined)
        .map_err(|_| AuthError::InvalidSignature)?;

    signed_message.verify(&public_key).map_err(|_| AuthError::InvalidSignature)?;

    let ts = timestamp.parse::<i64>().map_err(|_| AuthError::InvalidSignature)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs().cast_signed();

    if (now - ts).abs() > 15 {
        return Err(AuthError::TimestampExpired);
    }

    serde_json::from_str::<T>(&body).map_err(|_| AuthError::InvalidResponse)
}
