// SPDX-FileCopyrightText: 2026 BasedAuth
// SPDX-License-Identifier: Apache-2.0

#![warn(clippy::pedantic)]
#![deny(clippy::if_then_some_else_none)]
#![deny(clippy::option_if_let_else)]
#![deny(clippy::allow_attributes_without_reason)]
#![deny(clippy::implicit_clone)]
#![deny(clippy::get_unwrap)]
#![deny(clippy::str_to_string)]
#![allow(clippy::unreadable_literal, reason = "'Readable' literals are ugly")]

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
