// Copyright (c) 2025, The Ruskit Authors
// MIT License
// All rights reserved.

//! # Configs Builder
//!
//! `configs_builder` is a library that provides a flexible and extensible way to build application configurations
//! from various sources including environment variables and secret managers.
//!
//! It's part of the Ruskit framework and works in conjunction with the `configs` crate to provide a comprehensive
//! configuration management solution for Rust applications.
//!
//! ## Features
//!
//! - Configuration from environment variables with automatic loading based on environment
//! - Secret management integration with AWS Secrets Manager and local fallbacks
//! - Support for multiple environments (local, dev, staging, production)
//! - Support for various infrastructure configurations:
//!   - Message brokers: MQTT, RabbitMQ, Kafka
//!   - Databases: PostgreSQL, DynamoDB, SQLite
//!   - Cloud services: AWS, InfluxDB
//! - Observability configurations (metrics, tracing, health checks)
//! - Identity server integration for authentication and authorization
//!
//! ## Architecture
//!
//! The library follows a builder pattern, allowing applications to selectively enable only
//! the configuration components they need. Each component is loaded from environment variables
//! or secret managers based on the current application environment.
//!
//! ## Example
//!
//! ```rust
//! use configs_builder::ConfigBuilder;
//!
//! async fn setup_configs() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create a new configuration builder and enable only the components you need
//!     let (configs, otel_providers) = ConfigBuilder::new()
//!         .postgres()     // Enable PostgreSQL configuration
//!         .mqtt()         // Enable MQTT configuration
//!         .health()       // Enable health check endpoints
//!         .build::<MyDynamicConfigs>()
//!         .await?;
//!     
//!     // The configurations are now ready to use
//!     // otel_providers contains configured OpenTelemetry providers
//!     
//!     Ok(())
//! }
//! ```

mod configs_builder;
pub mod env_keys;
pub mod errors;

pub use configs_builder::ConfigBuilder;
