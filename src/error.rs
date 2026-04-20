// SPDX-FileCopyrightText: 2026 BasedAuth
// SPDX-License-Identifier: Apache-2.0

use core::fmt;

#[derive(Debug)]
pub enum AuthError {
    HwidMismatch,
    InvalidKey,
    InvalidResponse,
    InvalidSignature,
    ServiceUnavailable,
    TimestampExpired,
    Uninitialized
}

impl core::fmt::Display for AuthError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AuthError::HwidMismatch => write!(f, "Hardware ID mismatch"),
            AuthError::InvalidKey => write!(f, "Invalid key"),
            AuthError::InvalidResponse => write!(f, "Invalid response from server"),
            AuthError::InvalidSignature => write!(f, "Invalid signature"),
            AuthError::ServiceUnavailable => write!(f, "Service unavailable"),
            AuthError::TimestampExpired => write!(f, "Timestamp expired"),
            AuthError::Uninitialized => write!(f, "SDK not initialized")
        }
    }
}
