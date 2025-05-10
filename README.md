# Configs Builder

[![Crates.io](https://img.shields.io/crates/v/configs-builder.svg)](https://crates.io/crates/configs-builder)
[![Documentation](https://docs.rs/configs-builder/badge.svg)](https://docs.rs/configs-builder)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A flexible and extensible configuration builder for Rust applications, part of the Ruskit framework.

## Overview

`configs-builder` provides a fluent interface for building application configurations from various sources including environment variables and secret managers. It works in conjunction with the `configs` crate to provide a comprehensive configuration management solution for Rust applications.

## Features

- **Flexible Configuration Sources**: Load configurations from environment variables, .env files, or secret managers
- **Environment-Aware**: Support for multiple environments (local, development, staging, production)
- **Fluent Interface**: An ergonomic builder pattern for enabling only the configuration sections you need
- **Secrets Management**: Integration with AWS Secrets Manager or other secret providers
- **Infrastructure Configurations**: Support for:
  - Message Brokers: MQTT, RabbitMQ, Kafka
  - Databases: PostgreSQL, SQLite, DynamoDB
  - Monitoring: InfluxDB
  - Cloud Services: AWS
- **Observability**: Configuration for metrics, tracing, and health checks
- **Security**: Identity server integration

## Installation

Add `configs-builder` to your `Cargo.toml`:

```toml
[dependencies]
configs-builder = "0.0.1"
```

## Usage

### Basic Example

```rust
use configs_builder::ConfigBuilder;

async fn setup_configs() -> Result<configs::Configs<MyDynamicConfigs>, configs_builder::errors::ConfigsError> {
    let configs = ConfigBuilder::new()
        .postgres()
        .kafka()
        .metric()
        .trace()
        .build::<MyDynamicConfigs>()
        .await?;
    
    Ok(configs)
}
```

### Environment Variables

The library looks for environment variables or `.env` files based on the current environment:

- Local: `.env.local`
- Development: `.env.develop`
- Staging: `.env.staging`
- Production: `.env.prod`

### Secrets Management

Secret values in environment variables can be prefixed with `!` to indicate they should be retrieved from a secret manager:

```
DATABASE_PASSWORD=!my-db-password-secret
```

### Full Configuration Example

```rust
use configs_builder::ConfigBuilder;

async fn setup_configs() -> Result<configs::Configs<MyDynamicConfigs>, configs_builder::errors::ConfigsError> {
    let configs = ConfigBuilder::new()
        .mqtt()            // Enable MQTT configuration
        .rabbitmq()        // Enable RabbitMQ configuration
        .kafka()           // Enable Kafka configuration
        .postgres()        // Enable PostgreSQL configuration
        .sqlite()          // Enable SQLite configuration
        .dynamodb()        // Enable DynamoDB configuration 
        .influx()          // Enable InfluxDB configuration
        .aws()             // Enable AWS configuration
        .metric()          // Enable metrics configuration
        .trace()           // Enable tracing configuration
        .health()          // Enable health checks configuration
        .identity_server() // Enable identity server configuration
        .build::<MyDynamicConfigs>()
        .await?;
    
    Ok(configs)
}
```

## Documentation

For more detailed documentation, check the [API documentation](https://docs.rs/configs-builder).

## License

This project is licensed under the MIT License - see the LICENSE file for details.