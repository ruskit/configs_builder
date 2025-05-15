// Copyright (c) 2025, The Ruskit Authors
// MIT License
// All rights reserved.

//! # Errors
//!
//! Error types for the configs_builder crate.
//!
//! This module defines the error types that can occur during configuration building,
//! particularly related to secret management and internal operations.

use thiserror::Error;

/// Errors that can occur during configuration building.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum ConfigsError {
    /// Internal error that occurred during configuration building.
    #[error("internal error")]
    InternalError,

    #[error("failed to configure logging")]
    LoggingSetupError,

    /// Error that occurred while loading secrets from a secret manager.
    /// Contains a message with details about the error.
    #[error("error to load secrets from secret manager - `{0}`")]
    SecretLoadingError(String),
}
