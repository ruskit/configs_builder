// Copyright (c) 2025, The Ruskit Authors
// MIT License
// All rights reserved.

//! # Errors
//!
//! Error types for the configs_builder crate.
//!
//! This module defines the error types that can occur during configuration building,
//! particularly related to secret management, observability setup, and internal operations.
//! Using dedicated error types improves error handling and diagnostics throughout the
//! application.
//!
//! The errors in this module are designed to:
//! - Provide clear and specific error messages
//! - Enable proper error handling by consumers of the library
//! - Support structured logging for better error diagnostics

use thiserror::Error;

/// Errors that can occur during configuration building.
///
/// This enum represents the various error conditions that might arise during
/// the configuration building process. Each variant corresponds to a specific
/// error scenario and includes appropriate context information.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum ConfigsError {
    /// Internal error that occurred during configuration building.
    ///
    /// This is a general error type for unexpected failures that don't fit
    /// into the other more specific categories.
    #[error("internal error")]
    InternalError,

    /// Error that occurred while setting up the logging subsystem.
    ///
    /// This error indicates that there was an issue configuring or initializing
    /// the logging provider. Check for incorrect logging configuration or
    /// missing dependencies.
    #[error("failed to configure logging")]
    LoggingSetupError,

    /// Error that occurred while setting up the metrics subsystem.
    ///
    /// This error indicates that there was an issue configuring or initializing
    /// the metrics provider. Check for incorrect metrics configuration or
    /// missing dependencies.
    #[error("failed to configure metrics")]
    MetricsSetupError,

    /// Error that occurred while setting up the tracing subsystem.
    ///
    /// This error indicates that there was an issue configuring or initializing
    /// the traces provider. Check for incorrect tracing configuration or
    /// missing dependencies.
    #[error("failed to configure trace")]
    TracesSetupError,

    /// Error that occurred while loading secrets from a secret manager.
    ///
    /// This error provides details about failures in retrieving secrets from
    /// the configured secrets manager. The string payload contains specific
    /// information about what went wrong.
    ///
    /// # Arguments
    ///
    /// * `0` - A description of the secret loading error
    #[error("error to load secrets from secret manager - `{0}`")]
    SecretLoadingError(String),
}
