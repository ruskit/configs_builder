// Copyright (c) 2025, The Ruskit Authors
// MIT License
// All rights reserved.

//! # Environment Keys
//!
//! This module contains constant definitions for environment variable keys used throughout the
//! application for configuration purposes.
//!
//! These constants are used by the ConfigBuilder to read values from environment variables or
//! .env files, allowing for a flexible configuration mechanism across different environments.

/// Environment file names for different deployment environments
pub const LOCAL_ENV_FILE_NAME: &str = "./.env.local";
pub const DEV_ENV_FILE_NAME: &str = "./.env.develop";
pub const STAGING_FILE_NAME: &str = "./.env.staging";
pub const PROD_FILE_NAME: &str = "./.env.prod";

/// Secret management prefixes
pub const SECRET_PREFIX: &str = "!";
pub const SECRET_PREFIX_TO_DECODE: &str = "!!";
