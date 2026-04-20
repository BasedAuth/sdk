// SPDX-FileCopyrightText: 2026 BasedAuth
// SPDX-License-Identifier: Apache-2.0

mod auth;
mod error;
mod http;
mod hwid;
mod state;

const AUTH_URL: &str = "https://basedauth.com/api/sdk/authenticate";
