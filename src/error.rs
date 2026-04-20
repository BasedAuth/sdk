// SPDX-FileCopyrightText: 2026 BasedAuth
// SPDX-License-Identifier: Apache-2.0

#[derive(Debug)]
pub enum AuthError {
    AlreadyInitialized,
    ApplicationDisabled,
    HwidMismatch,
    InvalidHwid,
    InvalidKey,
    InvalidResponse,
    InvalidSignature,
    KeyExpired,
    ServiceUnavailable,
    TimestampExpired,
    Uninitialized
}

impl core::fmt::Display for AuthError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AuthError::AlreadyInitialized => write!(f, "SDK already initialized"),
            AuthError::ApplicationDisabled => write!(f, "Application disabled"),
            AuthError::HwidMismatch => write!(f, "Hardware ID mismatch"),
            AuthError::InvalidHwid => write!(f, "Invalid hardware ID"),
            AuthError::InvalidKey => write!(f, "Invalid key"),
            AuthError::InvalidResponse => write!(f, "Invalid response from server"),
            AuthError::InvalidSignature => write!(f, "Invalid signature"),
            AuthError::KeyExpired => write!(f, "Key expired"),
            AuthError::ServiceUnavailable => write!(f, "Service unavailable"),
            AuthError::TimestampExpired => write!(f, "Timestamp expired"),
            AuthError::Uninitialized => write!(f, "SDK not initialized")
        }
    }
}
