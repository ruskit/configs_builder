// Copyright (c) 2025, The Ruskit Authors
// MIT License
// All rights reserved.

//! # Environment Keys
//!
//! This module contains constant definitions for environment variable keys used throughout the
//! application for configuration purposes.
//!
//! These constants are used by the `ConfigBuilder` to read values from environment variables or
//! .env files, allowing for a flexible configuration mechanism across different environments.
//! The module provides a standardized way to reference environment variable names across the
//! application, ensuring consistency and avoiding typos or naming conflicts.
//!
//! ## Environment File Loading
//!
//! The library automatically loads the appropriate environment file based on the current
//! application environment (local, development, staging, or production).
//!
//! ## Secret Management
//!
//! Special prefixes are used to mark values that should be retrieved from a secrets manager
//! instead of directly from environment variables, enhancing security for sensitive information.

/// Environment file names for different deployment environments.
/// These files are loaded automatically based on the current application environment.
///
/// For local development environments.
pub const LOCAL_ENV_FILE_NAME: &str = "./.env.local";
/// For development environments.
pub const DEV_ENV_FILE_NAME: &str = "./.env.develop";
/// For staging environments.
pub const STAGING_FILE_NAME: &str = "./.env.staging";
/// For production environments.
pub const PROD_FILE_NAME: &str = "./.env.prod";

/// Secret management prefixes used to mark values that should be handled specially.
///
/// Prefix used to indicate that a value should be retrieved from the secrets manager.
/// When this prefix is detected, the configuration builder will attempt to fetch
/// the actual value from the configured secrets manager.
pub const SECRET_PREFIX: &str = "!";

/// Prefix used to indicate that a value should be retrieved from the secrets manager
/// and then base64 decoded. This is useful for binary secrets that are stored
/// in base64 format in the secrets manager.
pub const SECRET_PREFIX_TO_DECODE: &str = "!!";
