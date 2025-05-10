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
//! - Configuration from environment variables
//! - Secret management integration
//! - Support for multiple environments (local, dev, staging, production)
//! - Support for various infrastructure configurations (MQTT, RabbitMQ, Kafka, PostgreSQL, DynamoDB, etc.)
//! - Observability configurations (metrics, tracing, health checks)
//!
//! ## Example
//!
//! ```rust
//! use configs_builder::ConfigBuilder;
//!
//! async fn setup_configs() -> Result<(), Box<dyn std::error::Error>> {
//!     let configs = ConfigBuilder::new()
//!         .postgres()
//!         .metric()
//!         .trace()
//!         .build::<MyDynamicConfigs>()
//!         .await?;
//!     
//!     Ok(())
//! }
//! ```

mod configs_builder;
pub mod env_keys;
pub mod errors;

pub use configs_builder::ConfigBuilder;
