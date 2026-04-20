// SPDX-FileCopyrightText: 2026 BasedAuth
// SPDX-License-Identifier: Apache-2.0

mod auth;
mod constant;
mod error;
mod ffi;
mod http;
mod hwid;
mod state;

const AUTH_URL: &str = "https://basedauth.com/api/sdk/authenticate";
const CONSTANT_URL: &str = "https://basedauth.com/api/sdk/constant";
const REFRESH_URL: &str = "https://basedauth.com/api/sdk/refresh";
