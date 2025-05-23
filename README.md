# Configs Builder

[![Crates.io](https://img.shields.io/crates/v/configs-builder.svg)](https://crates.io/crates/configs-builder)
[![Documentation](https://docs.rs/configs-builder/badge.svg)](https://docs.rs/configs-builder)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A flexible and extensible configuration builder for Rust applications, part of the Ruskit framework.

## Overview

`configs-builder` provides a fluent interface for building application configurations from environment variables, .env files, and secret managers. It works in conjunction with the `configs` crate to provide a comprehensive configuration management solution for Rust applications that focuses on security, flexibility, and developer ergonomics.

The library follows a modular approach allowing developers to selectively enable only the configuration components their application needs, resulting in more efficient resource usage and clearer dependency specification.

## Key Features

- **Flexible Configuration Sources**
  - Environment variables with automatic detection and loading
  - Environment-specific .env files (`.env.local`, `.env.develop`, `.env.staging`, `.env.prod`)
  - Secret manager integration with transparent fallbacks

- **Three-Phase Configuration Architecture**
  1. **Initialization**: Select only the configuration components you need
  2. **Environment Loading**: Automatic loading based on current environment
  3. **Configuration Building**: Environment variable processing with secret resolution

- **First-Class Security**
  - Secure storage of sensitive values using AWS Secrets Manager
  - Secret reference syntax for sensitive environment variables
  - Identity server integration for authentication and authorization

- **Comprehensive Infrastructure Support**
  - **Message Brokers**: MQTT (with multi-broker support), RabbitMQ, Kafka
  - **Databases**: PostgreSQL, SQLite, DynamoDB
  - **Cloud Services**: AWS integration with credential management
  - **Monitoring**: InfluxDB for time-series data storage
  - **Health Checks**: Endpoints for container orchestration platforms

- **OpenTelemetry Integration**
  - Structured logging with configurable exporters
  - Metrics collection with customizable endpoints
  - Distributed tracing with sampling configuration

## Installation

Add `configs-builder` and its dependencies to your `Cargo.toml`:

```toml
[dependencies]
configs-builder = "0.0.1"

# The following Ruskit dependencies are recommended
# for a complete configuration experience
configs = { git = "https://github.com/ruskit/configs.git", rev = "beta-v0.0.4" }
```

> **Note:** This package is part of the Ruskit framework ecosystem. For best results, use the compatible versions of other Ruskit components.

## Usage

### Getting Started

The `ConfigBuilder` uses a fluent interface pattern, allowing you to selectively enable only the configuration components you need. This approach ensures that your application only loads configurations that are actually relevant to its operation.

```rust
use configs_builder::ConfigBuilder;
use configs::dynamic::DynamicConfigs;

// Define your application-specific dynamic configuration
struct MyAppConfigs {}

impl DynamicConfigs for MyAppConfigs {
    fn load(&mut self, _client: Arc<dyn SecretClient>) {
        // Application-specific configuration logic here
    }
}

async fn setup_configs() -> Result<configs::Configs<MyAppConfigs>, configs_builder::errors::ConfigsError> {
    // Create a new builder instance and enable only what you need
    let (configs, otel_providers) = ConfigBuilder::new()
        .postgres()   // Enable PostgreSQL configuration
        .mqtt()       // Enable MQTT configuration
        .health()     // Enable health check endpoints
        // Finalize the configuration with your dynamic configs
        .build::<MyAppConfigs>()
        .await?;
    
    // You now have a fully configured application with only the components you need
    Ok(configs)
}
```

### Environment Configuration

The library automatically detects the current environment and loads the appropriate configuration file:

| Environment | File Path      | Description                                      |
|-------------|---------------|--------------------------------------------------|
| Local       | `.env.local`   | For local development and testing                |
| Development | `.env.develop` | For development environments and CI/CD pipelines |
| Staging     | `.env.staging` | For pre-production staging environments          |
| Production  | `.env.prod`    | For production deployment                        |

The environment is determined by the `RUST_ENV` environment variable. If not set, it defaults to the local environment.

### Secrets Management

For sensitive information like database passwords or API keys, the library supports integration with AWS Secrets Manager and other secret providers. To reference a secret in your environment variables, prefix the value with `!`:

```dotenv
# Regular environment variables
DATABASE_HOST=localhost
DATABASE_PORT=5432

# Secret reference - will be fetched from the configured secret manager
DATABASE_PASSWORD=!my-db-password-secret
AWS_SECRET_ACCESS_KEY=!aws-secret-key

# Secrets can be used for any sensitive configuration
IDENTITY_SERVER_CLIENT_SECRET=!auth-client-secret
```

This approach allows you to keep sensitive information out of your codebase and environment files while still making it accessible to your application in a secure way.

### Complete Configuration Example

This example demonstrates using the `ConfigBuilder` to configure a full-featured application with multiple components:

```rust
use configs_builder::ConfigBuilder;
use std::sync::Arc;
use configs::dynamic::DynamicConfigs;
use secrets_manager::SecretClient;

// Your application-specific configuration
struct MyAppConfigs {
    custom_setting: String,
    feature_flags: Vec<String>,
}

impl DynamicConfigs for MyAppConfigs {
    fn load(&mut self, client: Arc<dyn SecretClient>) {
        // Load application-specific secrets if needed
        if let Ok(feature_flags) = client.get_by_key("!app-feature-flags") {
            self.feature_flags = serde_json::from_str(&feature_flags).unwrap_or_default();
        }
    }
}

async fn setup_app_config() -> anyhow::Result<()> {
    // Create and configure the builder
    let (configs, providers) = ConfigBuilder::new()
        // Message brokers
        .mqtt()            // Enable MQTT configuration
        .rabbitmq()        // Enable RabbitMQ configuration
        .kafka()           // Enable Kafka configuration
        
        // Databases
        .postgres()        // Enable PostgreSQL configuration
        .sqlite()          // Enable SQLite configuration
        .dynamodb()        // Enable DynamoDB configuration
        
        // Services and monitoring
        .influx()          // Enable InfluxDB configuration
        .aws()             // Enable AWS configuration
        .health()          // Enable health check endpoints
        .identity_server() // Enable identity server configuration
        
        // Build the final configuration
        .build::<MyAppConfigs>()
        .await?;
    
    // Initialize services with the configuration
    let db = database::connect(&configs.postgres)?;
    let mqtt_client = messaging::connect_mqtt(&configs.mqtt)?;
    let metrics = monitoring::setup(&configs.influx)?;
    
    // Use OpenTelemetry providers
    let _logger = providers.logger_provider();
    let _metrics = providers.metrics_provider();
    let _tracer = providers.trace_provider();
    
    // Application-specific configuration is available
    if configs.dynamic.feature_flags.contains(&"new-ui".to_string()) {
        // Enable new UI features
    }
    
    Ok(())
}
```

### Available Configuration Components

The builder provides methods for enabling various configuration components:

| Method            | Purpose                                         | Environment Variables                 |
|-------------------|------------------------------------------------|--------------------------------------|
| `mqtt()`          | MQTT messaging protocol support                 | `MQTT_HOST`, `MQTT_PORT`, etc.       |
| `rabbitmq()`      | RabbitMQ message broker support                 | `RABBITMQ_HOST`, `RABBITMQ_PORT`, etc. |
| `kafka()`         | Kafka distributed streaming platform            | `KAFKA_HOST`, `KAFKA_PORT`, etc.     |
| `postgres()`      | PostgreSQL database support                     | `POSTGRES_HOST`, `POSTGRES_USER`, etc. |
| `sqlite()`        | SQLite embedded database                        | `SQLITE_FILE_NAME`                   |
| `dynamodb()`      | AWS DynamoDB NoSQL database                     | `DYNAMO_TABLE`, `DYNAMO_REGION`, etc. |
| `influx()`        | InfluxDB time series database                   | `INFLUX_HOST`, `INFLUX_TOKEN`, etc.  |
| `aws()`           | AWS services integration                        | `AWS_ACCESS_KEY_ID`, etc.            |
| `health()`        | Health check endpoints                          | `HEALTH_READINESS_PORT`, etc.        |
| `identity_server()` | Identity and auth server integration          | `IDENTITY_SERVER_URL`, etc.          |

## OpenTelemetry Integration

The `ConfigBuilder` automatically sets up OpenTelemetry providers for:

- **Structured Logging**: Pre-configured logger for consistent log format across services
- **Metrics Collection**: Endpoints and collection configuration for application metrics
- **Distributed Tracing**: Trace context propagation across service boundaries

These providers are returned alongside your configuration when calling `build()` and can be used to instrument your application.

## Architecture

The `ConfigBuilder` follows a three-phase approach:

1. **Initialization Phase**: Users create a builder instance and enable specific components
2. **Environment Loading Phase**: Environment variables are loaded from the appropriate .env file
3. **Configuration Building Phase**: Environment values are processed and secrets are resolved

This approach ensures that configuration is loaded consistently across different environments while keeping sensitive information secure.

## Documentation

For more detailed documentation:

- [API Documentation](https://docs.rs/configs-builder): Comprehensive API reference
- [Example Applications](https://github.com/ruskit/examples): Sample projects using configs-builder
- [Ruskit Framework](https://github.com/ruskit): Explore the entire Ruskit ecosystem

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

© 2025 The Ruskit Authors