// Copyright (c) 2025, The Ruskit Authors
// MIT License
// All rights reserved.

//! # Configuration Builder
//!
//! This module provides the main `ConfigBuilder` implementation which is responsible for
//! building application configurations from environment variables and secret managers.
//!
//! The builder follows a fluent interface pattern, allowing users to selectively enable
//! different configuration sections based on their application's needs. This approach
//! ensures that only the necessary configuration components are loaded, improving
//! performance and reducing unnecessary dependencies.
//!
//! ## Architecture
//!
//! The `ConfigBuilder` works in three main phases:
//!
//! 1. **Initialization**: Users create a new builder instance and enable the specific
//!    configuration components they need (e.g., `postgres()`, `mqtt()`, `health()`, etc.).
//!
//! 2. **Environment Loading**: The builder automatically loads environment variables from
//!    the appropriate .env file based on the current application environment (local, dev,
//!    staging, or production).
//!
//! 3. **Configuration Building**: The builder processes environment variables, resolves
//!    secrets, and constructs a complete configuration object with all the required
//!    components.
//!
//! ## Secret Management
//!
//! The builder supports fetching sensitive configuration values from secret managers,
//! which enhances security by keeping secrets out of environment variables and source code.
//! Values prefixed with special markers (defined in `env_keys` module) are automatically
//! fetched from the configured secret manager.
//!
//! ## OpenTelemetry Integration
//!
//! The builder automatically sets up OpenTelemetry providers for logging, metrics, and
//! distributed tracing, providing a comprehensive observability solution.

use crate::{
    env_keys::{
        DEV_ENV_FILE_NAME, LOCAL_ENV_FILE_NAME, PROD_FILE_NAME, SECRET_PREFIX, STAGING_FILE_NAME,
    },
    errors::ConfigsError,
};
use base64::{Engine, engine::general_purpose};
use configs::{
    app::AppConfigs,
    aws::{AWS_DEFAULT_REGION, AWS_IAM_ACCESS_KEY_ID, AWS_IAM_SECRET_ACCESS_KEY},
    configs::Configs,
    dynamic::DynamicConfigs,
    dynamo::{
        DYNAMO_ENDPOINT_ENV_KEY, DYNAMO_EXPIRE_ENV_KEY, DYNAMO_REGION_ENV_KEY, DYNAMO_TABLE_ENV_KEY,
    },
    environment::Environment,
    health_readiness::{ENABLE_HEALTH_READINESS_ENV_KEY, HEALTH_READINESS_PORT_ENV_KEY},
    identity_server::{
        IDENTITY_SERVER_AUDIENCE_ENV_KEY, IDENTITY_SERVER_CLIENT_ID_ENV_KEY,
        IDENTITY_SERVER_CLIENT_SECRET_ENV_KEY, IDENTITY_SERVER_GRANT_TYPE_ENV_KEY,
        IDENTITY_SERVER_ISSUER_ENV_KEY, IDENTITY_SERVER_REALM_ENV_KEY, IDENTITY_SERVER_URL_ENV_KEY,
    },
    influx::{
        INFLUX_BUCKET_ENV_KEY, INFLUX_HOST_ENV_KEY, INFLUX_PORT_ENV_KEY, INFLUX_TOKEN_ENV_KEY,
    },
    kafka::{
        KAFKA_CA_PATH_KEY, KAFKA_CERTIFICATE_PATH_KEY, KAFKA_ENDPOINT_IDENTIFICATION_ALGORITHM_KEY,
        KAFKA_HOST_ENV_KEY, KAFKA_KEY_STORE_PASSWORD_KEY, KAFKA_KEY_STORE_PATH_KEY,
        KAFKA_PASSWORD_ENV_KEY, KAFKA_PORT_ENV_KEY, KAFKA_SASL_MECHANISMS_ENV_KEY,
        KAFKA_SECURITY_PROTOCOL_ENV_KEY, KAFKA_TIMEOUT_ENV_KEY, KAFKA_TRUST_STORE_PASSWORD_KEY,
        KAFKA_TRUST_STORE_PATH_KEY, KAFKA_USER_ENV_KEY,
    },
    mqtt::{
        MQTT_BROKER_KIND_ENV_KEY, MQTT_BROKERS_ENV_KEY, MQTT_CA_CERT_PATH_ENV_KEY,
        MQTT_HOST_ENV_KEY, MQTT_MULTI_BROKER_ENABLED_ENV_KEY, MQTT_PASSWORD_ENV_KEY,
        MQTT_PORT_ENV_KEY, MQTT_TRANSPORT_ENV_KEY, MQTT_USER_ENV_KEY, MQTTBrokerKind,
        MQTTConnectionConfigs, MQTTTransport,
    },
    otlp::{
        OTLP_ACCESS_KEY_ENV_KEY, OTLP_EXPORTER_ENDPOINT_ENV_KEY, OTLP_EXPORTER_INTERVAL_ENV_KEY,
        OTLP_EXPORTER_RATE_BASE_ENV_KEY, OTLP_EXPORTER_TIMEOUT_ENV_KEY, OTLP_EXPORTER_TYPE_ENV_KEY,
        OTLP_METRICS_ENABLED_ENV_KEY, OTLP_TRACES_ENABLED_KEY_ENV_KEY,
    },
    postgres::{
        POSTGRES_CA_PATH_ENV_KEY, POSTGRES_DB_ENV_KEY, POSTGRES_HOST_ENV_KEY,
        POSTGRES_PASSWORD_ENV_KEY, POSTGRES_PORT_ENV_KEY, POSTGRES_SSL_MODE_ENV_KEY,
        POSTGRES_USER_ENV_KEY,
    },
    rabbitmq::{
        RABBITMQ_HOST_ENV_KEY, RABBITMQ_PASSWORD_ENV_KEY, RABBITMQ_PORT_ENV_KEY,
        RABBITMQ_USER_ENV_KEY, RABBITMQ_VHOST_ENV_KEY,
    },
    secrets::SecretsManagerKind,
    sqlite::SQLITE_FILE_NAME_ENV_KEY,
};
use dotenvy::from_filename;
use logging;
use otel::providers::OtelProviders;
use secrets_manager::{AWSSecretClientBuilder, FakeSecretClient, SecretClient};
use std::{env, str::FromStr, sync::Arc, time::Duration};
use tracing::error;

/// The main configuration builder struct.
///
/// `ConfigBuilder` provides a fluent interface for building application configurations
/// from environment variables and secret managers. By default, all configuration sections
/// are disabled and must be explicitly enabled through the builder methods.
///
/// The builder follows the principle of only loading what's explicitly requested,
/// which helps to:
/// - Minimize resource usage by avoiding unnecessary configuration components
/// - Reduce startup time by loading only required configuration
/// - Provide clear dependency specification through the builder API
/// - Support flexible configuration combinations for different application types
///
/// # Example
///
/// ```rust
/// // Create a new builder instance
/// let (configs, otel_providers) = ConfigBuilder::new()
///     // Enable only the configuration components needed by your application
///     .postgres()   // Add PostgreSQL configuration
///     .mqtt()       // Add MQTT message broker configuration
///     .aws()        // Add AWS integration
///     .health()     // Add health check endpoints
///     // Finalize the configuration with application-specific dynamic configs
///     .build::<MyDynamicConfigs>()
///     .await?;
///
/// // Now you can use the configurations to initialize your application components
/// let db = postgres::connect(&configs.postgres).await?;
/// let mqtt_client = mqtt::connect(&configs.mqtt).await?;
/// ```
#[derive(Default)]
pub struct ConfigBuilder {
    client: Option<Arc<dyn SecretClient>>,
    mqtt: bool,
    rabbitmq: bool,
    kafka: bool,
    postgres: bool,
    dynamo: bool,
    sqlite: bool,
    influx: bool,
    aws: bool,
    health: bool,
    identity: bool,
    envs_already_loaded: bool,
}

impl ConfigBuilder {
    /// Creates a new instance of the `ConfigBuilder`.
    ///
    /// This is the entry point for constructing application configurations.
    /// By default, all configuration sections are disabled, and users must
    /// explicitly enable the ones they need using the builder methods.
    ///
    /// # Returns
    ///
    /// A new `ConfigBuilder` instance with all configuration sections disabled.
    ///
    /// # Example
    ///
    /// ```rust
    /// let builder = ConfigBuilder::new();
    /// ```
    pub fn new() -> ConfigBuilder {
        ConfigBuilder::default()
    }

    /// Loads environment variables from the appropriate .env file based on the current environment.
    ///
    /// This method automatically detects the current application environment (production,
    /// staging, development, or local) and loads the corresponding .env file into the
    /// process environment. The environment file paths are defined as constants in the
    /// `env_keys` module.
    ///
    /// Environment detection is based on the `RUST_ENV` environment variable:
    /// - "production" → Production environment (.env.prod)
    /// - "staging" → Staging environment (.env.staging)
    /// - "develop" → Development environment (.env.develop)
    /// - any other value or not set → Local environment (.env.local)
    ///
    /// If the environment file doesn't exist, the loading operation is silently ignored
    /// and the process continues with the existing environment variables.
    ///
    /// # Note
    ///
    /// This method is called automatically by `build()` if environment variables
    /// haven't been loaded yet, so manual invocation is usually unnecessary.
    pub fn load_envs(&self) {
        let env = Environment::from_rust_env();
        match env {
            Environment::Prod => {
                from_filename(PROD_FILE_NAME).ok();
            }
            Environment::Staging => {
                from_filename(STAGING_FILE_NAME).ok();
            }
            Environment::Dev => {
                from_filename(DEV_ENV_FILE_NAME).ok();
            }
            _ => {
                from_filename(LOCAL_ENV_FILE_NAME).ok();
            }
        }
    }

    /// Enables MQTT configuration.
    ///
    /// When enabled, the builder will attempt to load MQTT-related configuration from
    /// environment variables and configured secret managers. This method enables support
    /// for MQTT messaging protocols in your application.
    ///
    /// # Environment Variables
    ///
    /// The following environment variables are used to configure MQTT:
    /// - `MQTT_HOST`: The hostname or IP address of the MQTT broker
    /// - `MQTT_PORT`: The port number of the MQTT broker
    /// - `MQTT_USER`: Username for authentication with the MQTT broker
    /// - `MQTT_PASSWORD`: Password for authentication with the MQTT broker
    /// - `MQTT_TRANSPORT`: Transport protocol (tcp, ssl, ws, wss)
    /// - `MQTT_CA_CERT_PATH`: Path to the CA certificate file for SSL connections
    /// - `MQTT_BROKER_KIND`: The type of MQTT broker (emqx, rabbitmq, mosquitto, etc.)
    /// - `MQTT_MULTI_BROKER_ENABLED`: Whether to enable multiple broker connections
    /// - `MQTT_BROKERS`: Comma-separated list of broker endpoints for multi-broker mode
    ///
    /// # Returns
    ///
    /// The builder instance with MQTT configuration enabled, for method chaining.
    ///
    /// # Example
    ///
    /// ```rust
    /// let builder = ConfigBuilder::new().mqtt();
    /// ```
    pub fn mqtt(mut self) -> Self {
        self.mqtt = true;
        self
    }

    /// Enables RabbitMQ configuration.
    ///
    /// When enabled, the builder will attempt to load RabbitMQ-related configuration
    /// from environment variables and configured secret managers. This method enables
    /// support for RabbitMQ messaging in your application.
    ///
    /// # Environment Variables
    ///
    /// The following environment variables are used to configure RabbitMQ:
    /// - `RABBITMQ_HOST`: The hostname or IP address of the RabbitMQ server
    /// - `RABBITMQ_PORT`: The port number of the RabbitMQ server
    /// - `RABBITMQ_USER`: Username for authentication with the RabbitMQ server
    /// - `RABBITMQ_PASSWORD`: Password for authentication with the RabbitMQ server
    /// - `RABBITMQ_VHOST`: Virtual host to use on the RabbitMQ server
    ///
    /// # Returns
    ///
    /// The builder instance with RabbitMQ configuration enabled, for method chaining.
    ///
    /// # Example
    ///
    /// ```rust
    /// let builder = ConfigBuilder::new().rabbitmq();
    /// ```
    pub fn rabbitmq(mut self) -> Self {
        self.rabbitmq = true;
        self
    }

    /// Enables Kafka configuration.
    ///
    /// When enabled, the builder will attempt to load Kafka-related configuration
    /// from environment variables and configured secret managers. This method enables
    /// support for Kafka messaging in your application.
    ///
    /// # Environment Variables
    ///
    /// The following environment variables are used to configure Kafka:
    /// - `KAFKA_HOST`: The hostname or IP address of the Kafka broker
    /// - `KAFKA_PORT`: The port number of the Kafka broker
    /// - `KAFKA_USER`: Username for authentication with the Kafka broker
    /// - `KAFKA_PASSWORD`: Password for authentication with the Kafka broker
    /// - `KAFKA_SECURITY_PROTOCOL`: Security protocol (plaintext, ssl, sasl_plaintext, sasl_ssl)
    /// - `KAFKA_SASL_MECHANISMS`: SASL mechanisms (PLAIN, SCRAM-SHA-256, SCRAM-SHA-512, etc.)
    /// - `KAFKA_TIMEOUT`: Connection timeout in seconds
    /// - And several SSL-related configuration variables
    ///
    /// # Returns
    ///
    /// The builder instance with Kafka configuration enabled, for method chaining.
    ///
    /// # Example
    ///
    /// ```rust
    /// let builder = ConfigBuilder::new().kafka();
    /// ```
    pub fn kafka(mut self) -> Self {
        self.kafka = true;
        self
    }

    /// Enables PostgreSQL configuration.
    ///
    /// When enabled, the builder will attempt to load PostgreSQL-related configuration
    /// from environment variables and configured secret managers. This method enables
    /// support for PostgreSQL database connections in your application.
    ///
    /// # Environment Variables
    ///
    /// The following environment variables are used to configure PostgreSQL:
    /// - `POSTGRES_HOST`: The hostname or IP address of the PostgreSQL server
    /// - `POSTGRES_PORT`: The port number of the PostgreSQL server (default: 5432)
    /// - `POSTGRES_USER`: Username for authentication with the PostgreSQL server
    /// - `POSTGRES_PASSWORD`: Password for authentication with the PostgreSQL server
    /// - `POSTGRES_DB`: The name of the database to connect to
    /// - `POSTGRES_SSL_MODE`: SSL mode (disable, require, verify-ca, verify-full)
    /// - `POSTGRES_CA_PATH`: Path to the CA certificate file for SSL connections
    ///
    /// # Security Note
    ///
    /// For sensitive information like passwords, you can use the secret manager integration
    /// by prefixing the value with `!` in your environment file.
    ///
    /// # Returns
    ///
    /// The builder instance with PostgreSQL configuration enabled, for method chaining.
    ///
    /// # Example
    ///
    /// ```rust
    /// let builder = ConfigBuilder::new().postgres();
    /// ```
    pub fn postgres(mut self) -> Self {
        self.postgres = true;
        self
    }

    /// Enables SQLite configuration.
    ///
    /// When enabled, the builder will attempt to load SQLite-related configuration
    /// from environment variables. This method enables support for SQLite database
    /// connections in your application, which is particularly useful for local
    /// development, testing scenarios, or embedded applications.
    ///
    /// # Environment Variables
    ///
    /// The following environment variables are used to configure SQLite:
    /// - `SQLITE_FILE_NAME`: The path to the SQLite database file
    ///
    /// # Returns
    ///
    /// The builder instance with SQLite configuration enabled, for method chaining.
    ///
    /// # Example
    ///
    /// ```rust
    /// let builder = ConfigBuilder::new().sqlite();
    /// ```
    pub fn sqlite(mut self) -> Self {
        self.sqlite = true;
        self
    }

    /// Enables DynamoDB configuration.
    ///
    /// When enabled, the builder will attempt to load DynamoDB-related configuration
    /// from environment variables and configured secret managers. This method enables
    /// support for Amazon DynamoDB database connections in your application.
    ///
    /// # Environment Variables
    ///
    /// The following environment variables are used to configure DynamoDB:
    /// - `DYNAMO_ENDPOINT`: The endpoint URL for the DynamoDB service
    /// - `DYNAMO_REGION`: The AWS region where the DynamoDB table is located
    /// - `DYNAMO_TABLE`: The name of the DynamoDB table
    /// - `DYNAMO_EXPIRE`: The expiration time for items in the table (in seconds)
    ///
    /// # Note
    ///
    /// This method automatically enables AWS configuration as well, since DynamoDB
    /// is an AWS service that requires AWS credentials.
    ///
    /// # Returns
    ///
    /// The builder instance with DynamoDB configuration enabled, for method chaining.
    ///
    /// # Example
    ///
    /// ```rust
    /// let builder = ConfigBuilder::new().dynamodb();
    /// ```
    pub fn dynamodb(mut self) -> Self {
        self.dynamo = true;
        self
    }

    /// Enables InfluxDB configuration.
    ///
    /// When enabled, the builder will attempt to load InfluxDB-related configuration
    /// from environment variables and configured secret managers. This method enables
    /// support for InfluxDB time series database integration in your application, which
    /// is particularly useful for storing metrics, events, and other time series data.
    ///
    /// # Environment Variables
    ///
    /// The following environment variables are used to configure InfluxDB:
    /// - `INFLUX_HOST`: The hostname or URL of the InfluxDB server (default: "http://localhost")
    /// - `INFLUX_PORT`: The port number of the InfluxDB server (default: 8086)
    /// - `INFLUX_BUCKET`: The name of the bucket to store data in (default: "bucket")
    /// - `INFLUX_TOKEN`: The authentication token for InfluxDB API access (default: "token")
    ///
    /// # Security Note
    ///
    /// For sensitive information like tokens, you can use the secret manager integration
    /// by prefixing the value with `!` in your environment file.
    ///
    /// # Returns
    ///
    /// The builder instance with InfluxDB configuration enabled, for method chaining.
    ///
    /// # Example
    ///
    /// ```rust
    /// let builder = ConfigBuilder::new().influx();
    /// ```
    pub fn influx(mut self) -> Self {
        self.influx = true;
        self
    }

    /// Enables AWS configuration.
    ///
    /// When enabled, the builder will attempt to load AWS-related configuration
    /// from environment variables and configured secret managers. This method enables
    /// support for AWS services in your application and is automatically enabled when
    /// using AWS-specific services like DynamoDB.
    ///
    /// # Environment Variables
    ///
    /// The following environment variables are used to configure AWS authentication:
    /// - `AWS_ACCESS_KEY_ID`: The access key ID for AWS API authentication
    /// - `AWS_SECRET_ACCESS_KEY`: The secret access key for AWS API authentication
    ///
    /// # Security Note
    ///
    /// For sensitive information like AWS credentials, you can use the secret manager
    /// integration by prefixing the value with `!` in your environment file.
    ///
    /// # Returns
    ///
    /// The builder instance with AWS configuration enabled, for method chaining.
    ///
    /// # Example
    ///
    /// ```rust
    /// let builder = ConfigBuilder::new()
    ///     .aws()      // Enable AWS configuration
    ///     .dynamodb() // Also uses AWS configuration
    /// ```
    pub fn aws(mut self) -> Self {
        self.aws = true;
        self
    }

    /// Enables health and readiness check configuration.
    ///
    /// When enabled, the builder will attempt to load health check-related configuration
    /// from environment variables. Health and readiness endpoints are crucial for
    /// containerized applications and microservices to support orchestration platforms
    /// like Kubernetes, which use these endpoints to determine if a service is functioning
    /// properly and ready to receive traffic.
    ///
    /// # Environment Variables
    ///
    /// The following environment variables are used to configure health checks:
    /// - `ENABLE_HEALTH_READINESS`: Whether to enable health check endpoints (default: false)
    /// - `HEALTH_READINESS_PORT`: The port number to expose health check endpoints on (default: 8888)
    ///
    /// # Returns
    ///
    /// The builder instance with health check configuration enabled, for method chaining.
    ///
    /// # Example
    ///
    /// ```rust
    /// let builder = ConfigBuilder::new().health();
    /// ```
    pub fn health(mut self) -> Self {
        self.health = true;
        self
    }

    /// Enables identity server configuration.
    ///
    /// When enabled, the builder will attempt to load identity server-related configuration
    /// from environment variables and configured secret managers. This method enables
    /// support for authentication and authorization through an identity server (like
    /// Keycloak, Auth0, or other OAuth2/OpenID Connect providers).
    ///
    /// # Environment Variables
    ///
    /// The following environment variables are used to configure identity server integration:
    /// - `IDENTITY_SERVER_URL`: The base URL of the identity server (default: "http://localhost")
    /// - `IDENTITY_SERVER_REALM`: The realm name in the identity server (default: "localhost")
    /// - `IDENTITY_SERVER_AUDIENCE`: The audience parameter for token validation (default: "audience")
    /// - `IDENTITY_SERVER_ISSUER`: The issuer parameter for token validation (default: "issuer")
    /// - `IDENTITY_SERVER_GRANT_TYPE`: The OAuth2 grant type to use (default: "client_credentials")
    /// - `IDENTITY_SERVER_CLIENT_ID`: The client ID for authentication with the identity server
    /// - `IDENTITY_SERVER_CLIENT_SECRET`: The client secret for authentication with the identity server
    ///
    /// # Security Note
    ///
    /// Since identity server configuration typically contains sensitive credentials,
    /// it's strongly recommended to use the secret manager integration by prefixing
    /// values with `!` in your environment file, especially for client secrets.
    ///
    /// # Returns
    ///
    /// The builder instance with identity server configuration enabled, for method chaining.
    ///
    /// # Example
    ///
    /// ```rust
    /// let builder = ConfigBuilder::new().identity_server();
    /// ```
    pub fn identity_server(mut self) -> Self {
        self.identity = true;
        self
    }

    /// Builds the configuration based on the enabled configuration sections.
    ///
    /// This method is the final step in the configuration building process and performs
    /// the following operations:
    ///
    /// 1. Loads environment variables from the appropriate .env file based on the
    ///    application environment if they haven't been loaded already
    /// 2. Initializes a new `Configs<T>` instance with default values
    /// 3. Sets up the OpenTelemetry logging provider for structured logging
    /// 4. Initializes and configures the secret manager client based on application settings
    /// 5. Loads dynamic application-specific configurations
    /// 6. Processes all environment variables, filling in the configuration struct
    ///    with values from environment variables and secrets
    /// 7. Sets up metrics and distributed tracing providers
    /// 8. Returns the completed configuration along with the OpenTelemetry providers
    ///
    /// # Type Parameters
    ///
    /// * `T` - A type that implements the `DynamicConfigs` trait for application-specific
    ///         dynamic configuration. This allows for extending the configuration system
    ///         with custom application-specific settings.
    ///
    /// # Returns
    ///
    /// A `Result` containing a tuple with:
    /// - The populated `Configs<T>` struct containing all configuration values
    /// - `OtelProviders` containing the initialized OpenTelemetry providers for
    ///   logging, metrics, and distributed tracing
    ///
    /// Returns a `ConfigsError` if any part of the configuration process fails.
    ///
    /// # Errors
    ///
    /// This method can fail with the following errors:
    /// - `ConfigsError::LoggingSetupError` if the logging provider setup fails
    /// - `ConfigsError::MetricsSetupError` if the metrics provider setup fails
    /// - `ConfigsError::TracesSetupError` if the tracing provider setup fails
    /// - `ConfigsError::SecretLoadingError` if secret loading from the secret manager fails
    pub async fn build<'c, T>(&mut self) -> Result<(Configs<T>, OtelProviders), ConfigsError>
    where
        T: DynamicConfigs,
    {
        if !self.envs_already_loaded {
            self.load_envs();
            self.envs_already_loaded = true;
        }

        let mut cfg = Configs::<T>::default();
        cfg.app = AppConfigs::new();

        let logger_provider = match logging::provider::install() {
            Ok(p) => Ok(p),
            Err(err) => {
                error!(
                    error = ?err,
                    "failed to install logging provider"
                );
                Err(ConfigsError::LoggingSetupError)
            }
        }?;

        self.client = self.get_secret_client(&cfg.app).await?;
        cfg.dynamic.load(self.client.as_ref().unwrap().clone());

        for (key, value) in env::vars() {
            if self.fill_otlp(&mut cfg, &key, &value) {
                continue;
            };
            if self.fill_identity_server(&mut cfg, &key, &value) {
                continue;
            };
            if self.fill_mqtt(&mut cfg, &key, &value) {
                continue;
            };
            if self.fill_rabbitmq(&mut cfg, &key, &value) {
                continue;
            };
            if self.fill_kafka(&mut cfg, &key, &value) {
                continue;
            };
            if self.fill_postgres(&mut cfg, &key, &value) {
                continue;
            };
            if self.fill_dynamo(&mut cfg, &key, &value) {
                continue;
            };
            if self.fill_aws(&mut cfg, &key, &value) {
                continue;
            };
            if self.fill_health_readiness(&mut cfg, &key, &value) {
                continue;
            };
            if self.fill_sqlite(&mut cfg, &key, &value) {
                continue;
            };
            if self.fill_influx(&mut cfg, &key, &value) {
                continue;
            };
        }

        let metrics_provider = match metrics::provider::install() {
            Ok(p) => Ok(p),
            Err(err) => {
                error!(
                    error = ?err,
                    "failed to install metrics provider"
                );
                Err(ConfigsError::MetricsSetupError)
            }
        }?;

        let trace_provider = match traces::provider::install() {
            Ok(p) => Ok(p),
            Err(err) => {
                error!(
                    error = ?err,
                    "failed to install tracing provider"
                );
                Err(ConfigsError::TracesSetupError)
            }
        }?;

        let providers = OtelProviders::new(logger_provider, metrics_provider, trace_provider);

        Ok((cfg, providers))
    }
}

// Secret client implementation
impl ConfigBuilder {
    /// Creates and returns a secret client based on the application configuration.
    ///
    /// This method creates the appropriate secret client implementation based on the
    /// secret manager configuration in the application settings:
    ///
    /// - `SecretsManagerKind::None` - Creates a `FakeSecretClient` that simply returns
    ///   the plain values without any secret management. This is useful for development
    ///   and testing scenarios where a real secret manager is not available.
    ///
    /// - `SecretsManagerKind::AWSSecretManager` - Creates an AWS Secret Manager client
    ///   that retrieves secrets from AWS Secrets Manager service. This is the recommended
    ///   option for production environments where secure secret management is required.
    ///
    /// The method wraps the client in an `Arc` to enable safe sharing across threads
    /// and components.
    ///
    /// # Parameters
    ///
    /// * `app_cfg` - Application configuration containing secret manager settings,
    ///   including the secret manager kind and any necessary credentials.
    ///
    /// # Returns
    ///
    /// A `Result` containing an optional secret client wrapped in an `Arc` or a
    /// `ConfigsError::SecretLoadingError` if secret client creation fails.
    ///
    /// # Errors
    ///
    /// This method can fail with `ConfigsError::SecretLoadingError` if the AWS Secret
    /// Manager client cannot be created due to invalid credentials, network issues,
    /// or service unavailability.
    async fn get_secret_client(
        &self,
        app_cfg: &AppConfigs,
    ) -> Result<Option<Arc<dyn SecretClient>>, ConfigsError> {
        match app_cfg.secret_manager {
            SecretsManagerKind::None => Ok(Some(Arc::new(FakeSecretClient::new()))),

            SecretsManagerKind::AWSSecretManager => {
                match AWSSecretClientBuilder::new(app_cfg.secret_key.clone())
                    .build()
                    .await
                {
                    Ok(c) => Ok(Some(Arc::new(c))),
                    Err(err) => {
                        error!(error = err.to_string(), "error to create aws secret client");
                        Err(ConfigsError::SecretLoadingError(err.to_string()))
                    }
                }
            }
        }
    }
}

// Configuration filling methods
impl ConfigBuilder {
    /// Fills OpenTelemetry configuration from environment variables.
    ///
    /// This method processes environment variables related to OpenTelemetry (OTLP)
    /// configuration and updates the configuration object accordingly. OpenTelemetry
    /// provides a unified framework for distributed tracing, metrics collection,
    /// and logging across your application.
    ///
    /// The method automatically configures OTLP regardless of which features are
    /// enabled, as observability is a fundamental aspect of all applications.
    ///
    /// # Parameters
    ///
    /// * `cfg` - Mutable reference to the configuration being built.
    /// * `key` - Environment variable key related to OpenTelemetry configuration.
    /// * `value` - Environment variable value or secret reference.
    ///
    /// # Environment Variables
    ///
    /// - `OTLP_EXPORTER_TYPE`: The type of exporter to use ("stdout", "otlp", etc.)
    /// - `OTLP_EXPORTER_ENDPOINT`: The endpoint URL for the OTLP collector
    /// - `OTLP_ACCESS_KEY`: Access key for authentication with the OTLP collector
    /// - `OTLP_EXPORTER_TIMEOUT`: Timeout for exporter operations in seconds
    /// - `OTLP_EXPORTER_INTERVAL`: Interval between exports in seconds
    /// - `OTLP_EXPORTER_RATE_BASE`: Sampling rate for trace data (0.0-1.0)
    /// - `OTLP_METRICS_ENABLED`: Whether to enable metrics collection (true/false)
    /// - `OTLP_TRACES_ENABLED_KEY`: Whether to enable distributed tracing (true/false)
    ///
    /// # Returns
    ///
    /// `true` if the key was recognized as an OTLP configuration key and processed,
    /// `false` if the key is not related to OTLP configuration.
    fn fill_otlp<T>(
        &self,
        cfg: &mut Configs<T>,
        key: impl Into<std::string::String>,
        value: impl Into<std::string::String>,
    ) -> bool
    where
        T: DynamicConfigs,
    {
        match key.into().as_str() {
            OTLP_EXPORTER_TYPE_ENV_KEY => {
                let t: String = self.get_from_secret(value.into(), "stdout".into());
                cfg.otlp.exporter_type = t.as_str().into();
                true
            }
            OTLP_EXPORTER_ENDPOINT_ENV_KEY => {
                cfg.otlp.endpoint =
                    self.get_from_secret(value.into(), "http://localhost:4317".into());
                true
            }
            OTLP_ACCESS_KEY_ENV_KEY => {
                cfg.otlp.access_key = self.get_from_secret(value.into(), "access_key".into());
                true
            }
            OTLP_EXPORTER_TIMEOUT_ENV_KEY => {
                cfg.otlp.exporter_timeout =
                    Duration::from_secs(self.get_from_secret(value.into(), 60) as u64);
                true
            }
            OTLP_EXPORTER_INTERVAL_ENV_KEY => {
                cfg.otlp.exporter_interval =
                    Duration::from_secs(self.get_from_secret(value.into(), 60) as u64);
                true
            }
            OTLP_EXPORTER_RATE_BASE_ENV_KEY => {
                cfg.otlp.exporter_rate_base = self.get_from_secret(value.into(), 0.8).into();
                true
            }
            OTLP_METRICS_ENABLED_ENV_KEY => {
                cfg.otlp.metrics_enabled = self.get_from_secret(value.into(), false).into();
                true
            }
            OTLP_TRACES_ENABLED_KEY_ENV_KEY => {
                cfg.otlp.traces_enabled = self.get_from_secret(value.into(), false).into();
                true
            }
            _ => false,
        }
    }

    /// Fills identity server configuration from environment variables.
    ///
    /// This method processes environment variables related to identity server configuration
    /// and updates the configuration object accordingly. It handles authentication parameters
    /// for OAuth2/OpenID Connect providers like Keycloak, Auth0, etc.
    ///
    /// The method supports retrieving sensitive configuration values (like client secrets)
    /// from a secret manager when the values are prefixed with the secret prefix.
    ///
    /// # Identity Server Configuration
    ///
    /// The identity server integration supports standard OAuth2/OpenID Connect flows,
    /// particularly focusing on the client credentials flow for service-to-service
    /// authentication and JWT token validation for user authentication.
    ///
    /// # Parameters
    ///
    /// * `cfg` - Mutable reference to the configuration being built.
    /// * `key` - Environment variable key for the identity server configuration.
    /// * `value` - Environment variable value or secret reference.
    ///
    /// # Returns
    ///
    /// `true` if the key was recognized and processed, `false` if the key is not
    /// related to identity server configuration.
    fn fill_identity_server<T>(
        &self,
        cfg: &mut Configs<T>,
        key: impl Into<std::string::String>,
        value: impl Into<std::string::String>,
    ) -> bool
    where
        T: DynamicConfigs,
    {
        if !self.identity {
            return false;
        }

        match key.into().as_str() {
            IDENTITY_SERVER_URL_ENV_KEY => {
                cfg.identity.url = self.get_from_secret(value.into(), "http://localhost".into());
                true
            }
            IDENTITY_SERVER_REALM_ENV_KEY => {
                cfg.identity.realm = self.get_from_secret(value.into(), "localhost".into());
                true
            }
            IDENTITY_SERVER_AUDIENCE_ENV_KEY => {
                cfg.identity.audience = self.get_from_secret(value.into(), "audience".into());
                true
            }
            IDENTITY_SERVER_ISSUER_ENV_KEY => {
                cfg.identity.issuer = self.get_from_secret(value.into(), "issuer".into());
                true
            }
            IDENTITY_SERVER_GRANT_TYPE_ENV_KEY => {
                cfg.identity.grant_type =
                    self.get_from_secret(value.into(), "client_credentials".into());
                true
            }
            IDENTITY_SERVER_CLIENT_ID_ENV_KEY => {
                cfg.identity.client_id = self.get_from_secret(value.into(), "".into());
                true
            }
            IDENTITY_SERVER_CLIENT_SECRET_ENV_KEY => {
                cfg.identity.client_secret = self.get_from_secret(value.into(), "".into());
                true
            }
            _ => false,
        }
    }

    /// Fills MQTT configuration from environment variables.
    ///
    /// This method processes environment variables related to MQTT configuration and
    /// updates the configuration object accordingly. MQTT is a lightweight publish/subscribe
    /// messaging protocol designed for IoT and other scenarios requiring efficient
    /// message delivery with minimal bandwidth usage.
    ///
    /// The method supports both single-broker and multi-broker configurations. When
    /// multi-broker mode is enabled (via `MQTT_MULTI_BROKER_ENABLED`), it can parse
    /// a JSON array of broker configurations from the `MQTT_BROKERS` environment variable.
    ///
    /// The method is only active when the MQTT feature has been explicitly enabled
    /// through the `mqtt()` method on the configuration builder.
    ///
    /// # Parameters
    ///
    /// * `cfg` - Mutable reference to the configuration being built.
    /// * `key` - Environment variable key related to MQTT configuration.
    /// * `value` - Environment variable value or secret reference.
    ///
    /// # Environment Variables
    ///
    /// - `MQTT_HOST`: Hostname or IP address of the broker (default: "localhost")
    /// - `MQTT_PORT`: Port number for the MQTT broker (default: 1883)
    /// - `MQTT_USER`: Username for authentication (default: "mqtt")
    /// - `MQTT_PASSWORD`: Password for authentication (default: "password")
    /// - `MQTT_TRANSPORT`: Transport protocol - "tcp", "ssl", "ws", "wss" (default: "tcp")
    /// - `MQTT_CA_CERT_PATH`: Path to CA certificate for SSL connections (default: "")
    /// - `MQTT_BROKER_KIND`: Type of MQTT broker (default: "default")
    /// - `MQTT_MULTI_BROKER_ENABLED`: Whether to use multiple brokers (default: false)
    /// - `MQTT_BROKERS`: JSON array of broker configurations for multi-broker mode
    ///
    /// # Returns
    ///
    /// `true` if the key was recognized as an MQTT configuration key and processed,
    /// `false` if the key is not related to MQTT or if the MQTT feature is not enabled.
    /// Fills MQTT configuration from environment variables.
    ///
    /// This method processes environment variables related to MQTT configuration and
    /// updates the configuration object accordingly. MQTT is a lightweight publish/subscribe
    /// messaging protocol designed for IoT and other scenarios requiring efficient
    /// message delivery with minimal bandwidth usage.
    ///
    /// The method supports both single-broker and multi-broker configurations. When
    /// multi-broker mode is enabled (via `MQTT_MULTI_BROKER_ENABLED`), it can parse
    /// a JSON array of broker configurations from the `MQTT_BROKERS` environment variable.
    ///
    /// The method is only active when the MQTT feature has been explicitly enabled
    /// through the `mqtt()` method on the configuration builder.
    ///
    /// # Parameters
    ///
    /// * `cfg` - Mutable reference to the configuration being built.
    /// * `key` - Environment variable key related to MQTT configuration.
    /// * `value` - Environment variable value or secret reference.
    ///
    /// # Environment Variables
    ///
    /// - `MQTT_HOST`: Hostname or IP address of the broker (default: "localhost")
    /// - `MQTT_PORT`: Port number for the MQTT broker (default: 1883)
    /// - `MQTT_USER`: Username for authentication (default: "mqtt")
    /// - `MQTT_PASSWORD`: Password for authentication (default: "password")
    /// - `MQTT_TRANSPORT`: Transport protocol - "tcp", "ssl", "ws", "wss" (default: "tcp")
    /// - `MQTT_CA_CERT_PATH`: Path to CA certificate for SSL connections (default: "")
    /// - `MQTT_BROKER_KIND`: Type of MQTT broker (default: "default")
    /// - `MQTT_MULTI_BROKER_ENABLED`: Whether to use multiple brokers (default: false)
    /// - `MQTT_BROKERS`: JSON array of broker configurations for multi-broker mode
    ///
    /// # Returns
    ///
    /// `true` if the key was recognized as an MQTT configuration key and processed,
    /// `false` if the key is not related to MQTT or if the MQTT feature is not enabled.
    fn fill_mqtt<T>(
        &self,
        cfg: &mut Configs<T>,
        key: impl Into<std::string::String>,
        value: impl Into<std::string::String>,
    ) -> bool
    where
        T: DynamicConfigs,
    {
        if !self.mqtt {
            return false;
        }

        if env::var(MQTT_MULTI_BROKER_ENABLED_ENV_KEY).unwrap_or_default() == "true" {
            cfg.mqtt.multi_broker_enabled = true;
        }

        let key: String = key.into();

        if cfg.mqtt.multi_broker_enabled && key.eq(MQTT_BROKERS_ENV_KEY) {
            let v = self.get_from_secret::<String>(value.into(), "[{}]".into());

            match serde_json::from_str::<Vec<MQTTConnectionConfigs>>(&v) {
                Err(err) => {
                    error!(
                        error = err.to_string(),
                        "failed to parse connections config for multi broker configurations"
                    );

                    panic!("failed to parse connections config for multi broker configurations");
                }
                Ok(configs) => {
                    cfg.mqtt.connection_configs = configs;
                }
            }

            return true;
        }

        match key.as_str() {
            MQTT_BROKER_KIND_ENV_KEY => {
                let kind = self.get_from_secret::<String>(value.into(), "default".into());
                cfg.mqtt.connection_configs[0].broker_kind = MQTTBrokerKind::from(&kind);
                true
            }
            MQTT_HOST_ENV_KEY => {
                cfg.mqtt.connection_configs[0].host =
                    self.get_from_secret(value.into(), "localhost".into());
                true
            }
            MQTT_TRANSPORT_ENV_KEY => {
                let transport = self.get_from_secret::<String>(value.into(), "tcp".into());
                cfg.mqtt.connection_configs[0].transport = MQTTTransport::from(&transport);
                true
            }
            MQTT_PORT_ENV_KEY => {
                cfg.mqtt.connection_configs[0].port = self.get_from_secret(value.into(), 1883);
                true
            }
            MQTT_USER_ENV_KEY => {
                cfg.mqtt.connection_configs[0].user =
                    self.get_from_secret(value.into(), "mqtt".into());
                true
            }
            MQTT_PASSWORD_ENV_KEY => {
                cfg.mqtt.connection_configs[0].password =
                    self.get_from_secret(value.into(), "password".into());
                true
            }
            MQTT_CA_CERT_PATH_ENV_KEY => {
                cfg.mqtt.connection_configs[0].root_ca_path =
                    self.get_from_secret(value.into(), "".into());
                true
            }
            _ => false,
        }
    }

    /// Fills RabbitMQ configuration from environment variables.
    ///
    /// This method processes environment variables related to RabbitMQ configuration
    /// and updates the configuration object accordingly. RabbitMQ is a robust message
    /// broker that implements AMQP (Advanced Message Queuing Protocol) and provides
    /// features like message persistence, routing, and clustering.
    ///
    /// The method is only active when the RabbitMQ feature has been explicitly enabled
    /// through the `rabbitmq()` method on the configuration builder.
    ///
    /// # Parameters
    ///
    /// * `cfg` - Mutable reference to the configuration being built.
    /// * `key` - Environment variable key related to RabbitMQ configuration.
    /// * `value` - Environment variable value or secret reference.
    ///
    /// # Environment Variables
    ///
    /// - `RABBITMQ_HOST`: Hostname or IP address of the RabbitMQ server (default: "localhost")
    /// - `RABBITMQ_PORT`: Port number for the RabbitMQ server (default: 5672)
    /// - `RABBITMQ_USER`: Username for authentication (default: "guest")
    /// - `RABBITMQ_PASSWORD`: Password for authentication (default: "guest")
    /// - `RABBITMQ_VHOST`: Virtual host to use (default: "")
    ///
    /// # Security Note
    ///
    /// For sensitive information like passwords, you can use the secret manager integration
    /// by prefixing the value with `!` in your environment file.
    ///
    /// # Returns
    ///
    /// `true` if the key was recognized as a RabbitMQ configuration key and processed,
    /// `false` if the key is not related to RabbitMQ or if the RabbitMQ feature is not enabled.
    fn fill_rabbitmq<T>(
        &self,
        cfg: &mut Configs<T>,
        key: impl Into<std::string::String>,
        value: impl Into<std::string::String>,
    ) -> bool
    where
        T: DynamicConfigs,
    {
        if !self.rabbitmq {
            return false;
        }

        match key.into().as_str() {
            RABBITMQ_HOST_ENV_KEY => {
                cfg.rabbitmq.host = self.get_from_secret(value.into(), "localhost".into());
                true
            }
            RABBITMQ_PORT_ENV_KEY => {
                cfg.rabbitmq.port = self.get_from_secret(value.into(), 5672);
                true
            }
            RABBITMQ_USER_ENV_KEY => {
                cfg.rabbitmq.user = self.get_from_secret(value.into(), "guest".into());
                true
            }
            RABBITMQ_PASSWORD_ENV_KEY => {
                cfg.rabbitmq.password = self.get_from_secret(value.into(), "guest".into());
                true
            }
            RABBITMQ_VHOST_ENV_KEY => {
                cfg.rabbitmq.vhost = self.get_from_secret(value.into(), "".into());
                true
            }
            _ => false,
        }
    }

    /// Fills Kafka configuration from environment variables.
    ///
    /// # Parameters
    ///
    /// * `cfg` - Mutable reference to the configuration being built.
    /// * `key` - Environment variable key.
    /// * `value` - Environment variable value.
    ///
    /// # Returns
    ///
    /// `true` if the key was recognized and processed, `false` otherwise.
    fn fill_kafka<T>(
        &self,
        cfg: &mut Configs<T>,
        key: impl Into<std::string::String>,
        value: impl Into<std::string::String>,
    ) -> bool
    where
        T: DynamicConfigs,
    {
        if !self.kafka {
            return false;
        }

        match key.into().as_str() {
            KAFKA_HOST_ENV_KEY => {
                cfg.kafka.host = self.get_from_secret(value.into(), "localhost".into());
                true
            }
            KAFKA_PORT_ENV_KEY => {
                cfg.kafka.port = self.get_from_secret(value.into(), 9094);
                true
            }
            KAFKA_TIMEOUT_ENV_KEY => {
                cfg.kafka.timeout = self.get_from_secret(value.into(), 6000);
                true
            }
            KAFKA_SECURITY_PROTOCOL_ENV_KEY => {
                cfg.kafka.security_protocol = self.get_from_secret(value.into(), "SASL_SSL".into());
                true
            }
            KAFKA_SASL_MECHANISMS_ENV_KEY => {
                cfg.kafka.sasl_mechanisms = self.get_from_secret(value.into(), "PLAIN".into());
                true
            }
            KAFKA_CERTIFICATE_PATH_KEY => {
                cfg.kafka.certificate_path =
                    self.get_from_secret(value.into(), "/certs/certificate.pem".into());
                true
            }
            KAFKA_CA_PATH_KEY => {
                cfg.kafka.ca_path = self.get_from_secret(value.into(), "/certs/ca.pem".into());
                true
            }
            KAFKA_TRUST_STORE_PATH_KEY => {
                cfg.kafka.trust_store_path =
                    self.get_from_secret(value.into(), "/certs/trust.pem".into());
                true
            }
            KAFKA_TRUST_STORE_PASSWORD_KEY => {
                cfg.kafka.trust_store_password =
                    self.get_from_secret(value.into(), "password".into());
                true
            }
            KAFKA_KEY_STORE_PATH_KEY => {
                cfg.kafka.key_store_path =
                    self.get_from_secret(value.into(), "/certs/key.pem".into());
                true
            }
            KAFKA_KEY_STORE_PASSWORD_KEY => {
                cfg.kafka.key_store_password =
                    self.get_from_secret(value.into(), "password".into());
                true
            }
            KAFKA_ENDPOINT_IDENTIFICATION_ALGORITHM_KEY => {
                cfg.kafka.endpoint_identification_algorithm =
                    self.get_from_secret(value.into(), "https".into());
                true
            }
            KAFKA_USER_ENV_KEY => {
                cfg.kafka.user = self.get_from_secret(value.into(), "user".into());
                true
            }
            KAFKA_PASSWORD_ENV_KEY => {
                cfg.kafka.password = self.get_from_secret(value.into(), "password".into());
                true
            }
            _ => false,
        }
    }

    /// Fills PostgreSQL configuration from environment variables.
    ///
    /// This method processes environment variables related to PostgreSQL configuration
    /// and updates the configuration object accordingly. PostgreSQL is a powerful,
    /// open-source object-relational database system with a strong reputation for
    /// reliability, feature robustness, and performance.
    ///
    /// The method is only active when the PostgreSQL feature has been explicitly enabled
    /// through the `postgres()` method on the configuration builder.
    ///
    /// # Parameters
    ///
    /// * `cfg` - Mutable reference to the configuration being built.
    /// * `key` - Environment variable key related to PostgreSQL configuration.
    /// * `value` - Environment variable value or secret reference.
    ///
    /// # Environment Variables
    ///
    /// - `POSTGRES_HOST`: Hostname or IP address of the PostgreSQL server (default: "localhost")
    /// - `POSTGRES_PORT`: Port number for the PostgreSQL server (default: 5432)
    /// - `POSTGRES_USER`: Username for authentication (default: "postgres")
    /// - `POSTGRES_PASSWORD`: Password for authentication (default: "postgres")
    /// - `POSTGRES_DB`: Database name to connect to (default: "hdr")
    /// - `POSTGRES_SSL_MODE`: SSL mode to use (default: "disabled")
    /// - `POSTGRES_CA_PATH`: Path to CA certificate for SSL verification (default: "")
    ///
    /// # Security Note
    ///
    /// For sensitive information like passwords, you can use the secret manager integration
    /// by prefixing the value with `!` in your environment file.
    ///
    /// # Returns
    ///
    /// `true` if the key was recognized as a PostgreSQL configuration key and processed,
    /// `false` if the key is not related to PostgreSQL or if the PostgreSQL feature is not enabled.
    fn fill_postgres<T>(
        &self,
        cfg: &mut Configs<T>,
        key: impl Into<std::string::String>,
        value: impl Into<std::string::String>,
    ) -> bool
    where
        T: DynamicConfigs,
    {
        if !self.postgres {
            return false;
        }

        match key.into().as_str() {
            POSTGRES_HOST_ENV_KEY => {
                cfg.postgres.host = self.get_from_secret(value.into(), "localhost".into());
                true
            }
            POSTGRES_USER_ENV_KEY => {
                cfg.postgres.user = self.get_from_secret(value.into(), "postgres".into());
                true
            }
            POSTGRES_PASSWORD_ENV_KEY => {
                cfg.postgres.password = self.get_from_secret(value.into(), "postgres".into());
                true
            }
            POSTGRES_PORT_ENV_KEY => {
                cfg.postgres.port = self.get_from_secret(value.into(), 5432);
                true
            }
            POSTGRES_DB_ENV_KEY => {
                cfg.postgres.db = self.get_from_secret(value.into(), "hdr".into());
                true
            }
            POSTGRES_SSL_MODE_ENV_KEY => {
                let ssl_mode: String = self.get_from_secret(value.into(), "disabled".into());
                cfg.postgres.ssl_mode = ssl_mode.into();
                true
            }
            POSTGRES_CA_PATH_ENV_KEY => {
                cfg.postgres.ca_path = self.get_from_secret(value.into(), "".into());
                true
            }
            _ => false,
        }
    }

    /// Fills DynamoDB configuration from environment variables.
    ///
    /// This method processes environment variables related to Amazon DynamoDB configuration
    /// and updates the configuration object accordingly. DynamoDB is a fully managed NoSQL
    /// database service provided by AWS, offering fast and predictable performance with
    /// seamless scalability.
    ///
    /// The method is only active when the DynamoDB feature has been explicitly enabled
    /// through the `dynamodb()` method on the configuration builder.
    ///
    /// # Parameters
    ///
    /// * `cfg` - Mutable reference to the configuration being built.
    /// * `key` - Environment variable key related to DynamoDB configuration.
    /// * `value` - Environment variable value or secret reference.
    ///
    /// # Environment Variables
    ///
    /// - `DYNAMO_ENDPOINT`: The endpoint URL for the DynamoDB service (default: "localhost")
    /// - `DYNAMO_TABLE`: The name of the table to use in DynamoDB (default: "table")
    /// - `DYNAMO_REGION`: The AWS region where the table is located (default: AWS_DEFAULT_REGION or "us-east-1")
    /// - `DYNAMO_EXPIRE`: The expiration time for items in seconds (default: 31536000, or 1 year)
    ///
    /// # Returns
    ///
    /// `true` if the key was recognized as a DynamoDB configuration key and processed,
    /// `false` if the key is not related to DynamoDB or if the DynamoDB feature is not enabled.
    fn fill_dynamo<T>(
        &self,
        cfg: &mut Configs<T>,
        key: impl Into<std::string::String>,
        value: impl Into<std::string::String>,
    ) -> bool
    where
        T: DynamicConfigs,
    {
        if !self.dynamo {
            return false;
        }

        match key.into().as_str() {
            DYNAMO_ENDPOINT_ENV_KEY => {
                cfg.dynamo.endpoint = self.get_from_secret(value.into(), "localhost".into());
                true
            }
            DYNAMO_TABLE_ENV_KEY => {
                cfg.dynamo.table = self.get_from_secret(value.into(), "table".into());
                true
            }
            DYNAMO_REGION_ENV_KEY => {
                cfg.dynamo.region = self.get_from_secret(value.into(), AWS_DEFAULT_REGION.into());
                true
            }
            DYNAMO_EXPIRE_ENV_KEY => {
                cfg.dynamo.expire = self.get_from_secret(value.into(), 31536000);
                true
            }
            _ => false,
        }
    }

    /// Fills AWS configuration from environment variables.
    ///
    /// This method processes environment variables related to AWS authentication and
    /// updates the configuration object accordingly. AWS credentials are used for
    /// authentication with various AWS services like DynamoDB, S3, Secrets Manager, etc.
    ///
    /// The method is only active when the AWS feature has been explicitly enabled
    /// through the `aws()` method on the configuration builder, or implicitly via
    /// other AWS service methods like `dynamodb()`.
    ///
    /// # Parameters
    ///
    /// * `cfg` - Mutable reference to the configuration being built.
    /// * `key` - Environment variable key related to AWS configuration.
    /// * `value` - Environment variable value or secret reference.
    ///
    /// # Environment Variables
    ///
    /// - `AWS_ACCESS_KEY_ID`: The access key ID for AWS API authentication (default: "key")
    /// - `AWS_SECRET_ACCESS_KEY`: The secret access key for AWS API authentication (default: "secret")
    ///
    /// # Security Note
    ///
    /// Since AWS credentials provide access to potentially sensitive cloud resources,
    /// it's strongly recommended to use the secret manager integration by prefixing values
    /// with `!` in your environment file, especially for production environments.
    ///
    /// # Returns
    ///
    /// `true` if the key was recognized as an AWS configuration key and processed,
    /// `false` if the key is not related to AWS or if the AWS feature is not enabled.
    fn fill_aws<T>(
        &self,
        cfg: &mut Configs<T>,
        key: impl Into<std::string::String>,
        value: impl Into<std::string::String>,
    ) -> bool
    where
        T: DynamicConfigs,
    {
        if !self.aws {
            return false;
        }

        match key.into().as_str() {
            AWS_IAM_ACCESS_KEY_ID => {
                cfg.aws.access_key_id = Some(self.get_from_secret(value.into(), "key".into()));
                true
            }
            AWS_IAM_SECRET_ACCESS_KEY => {
                cfg.aws.secret_access_key =
                    Some(self.get_from_secret(value.into(), "secret".into()));
                true
            }
            _ => false,
        }
    }

    /// Fills health and readiness check configuration from environment variables.
    ///
    /// This method processes environment variables related to health and readiness check
    /// configuration and updates the configuration object accordingly. Health checks are
    /// crucial for containerized applications and microservices, as they allow orchestration
    /// systems like Kubernetes to monitor the application's status.
    ///
    /// The method is only active when the health feature has been explicitly enabled
    /// through the `health()` method on the configuration builder.
    ///
    /// # Parameters
    ///
    /// * `cfg` - Mutable reference to the configuration being built.
    /// * `key` - Environment variable key related to health check configuration.
    /// * `value` - Environment variable value or secret reference.
    ///
    /// # Environment Variables
    ///
    /// - `HEALTH_READINESS_PORT`: The port number to expose health check endpoints on (default: 8888)
    /// - `ENABLE_HEALTH_READINESS`: Whether to enable health check endpoints (default: false)
    ///
    /// # Returns
    ///
    /// `true` if the key was recognized as a health check configuration key and processed,
    /// `false` if the key is not related to health checks or if the health feature is not enabled.
    fn fill_health_readiness<T>(
        &self,
        cfg: &mut Configs<T>,
        key: impl Into<std::string::String>,
        value: impl Into<std::string::String>,
    ) -> bool
    where
        T: DynamicConfigs,
    {
        if !self.health {
            return false;
        }

        match key.into().as_str() {
            HEALTH_READINESS_PORT_ENV_KEY => {
                cfg.health_readiness.port = self.get_from_secret(value.into(), 8888);
                true
            }
            ENABLE_HEALTH_READINESS_ENV_KEY => {
                cfg.health_readiness.enable = self.get_from_secret(value.into(), false);
                true
            }
            _ => false,
        }
    }

    /// Fills SQLite configuration from environment variables.
    ///
    /// This method processes environment variables related to SQLite configuration
    /// and updates the configuration object accordingly. SQLite is a lightweight,
    /// file-based relational database that's ideal for embedded applications, local
    /// development, and testing.
    ///
    /// The method is only active when the SQLite feature has been explicitly enabled
    /// through the `sqlite()` method on the configuration builder.
    ///
    /// # Parameters
    ///
    /// * `cfg` - Mutable reference to the configuration being built.
    /// * `key` - Environment variable key related to SQLite configuration.
    /// * `value` - Environment variable value or secret reference.
    ///
    /// # Environment Variables
    ///
    /// - `SQLITE_FILE_NAME`: The file path for the SQLite database (default: "local.db")
    ///
    /// # Returns
    ///
    /// `true` if the key was recognized as a SQLite configuration key and processed,
    /// `false` if the key is not related to SQLite configuration or if the SQLite
    /// feature is not enabled.
    fn fill_sqlite<T>(
        &self,
        cfg: &mut Configs<T>,
        key: impl Into<std::string::String>,
        value: impl Into<std::string::String>,
    ) -> bool
    where
        T: DynamicConfigs,
    {
        if !self.sqlite {
            return false;
        }

        match key.into().as_str() {
            SQLITE_FILE_NAME_ENV_KEY => {
                cfg.sqlite.file = self.get_from_secret(value.into(), "local.db".into());
                true
            }
            _ => false,
        }
    }

    /// Fills InfluxDB configuration from environment variables.
    ///
    /// This method processes environment variables related to InfluxDB configuration
    /// and updates the configuration object accordingly. It sets up the connection
    /// parameters for the InfluxDB time series database, which is commonly used for
    /// storing metrics, events, and other time series data.
    ///
    /// Unlike most other `fill_` methods, this one does not check whether the InfluxDB
    /// feature was enabled with `influx()`, allowing for the configuration to be loaded
    /// if the environment variables are present regardless of explicit enablement.
    ///
    /// # Parameters
    ///
    /// * `cfg` - Mutable reference to the configuration being built.
    /// * `key` - Environment variable key related to InfluxDB configuration.
    /// * `value` - Environment variable value or secret reference.
    ///
    /// # Default Values
    ///
    /// - Host: "http://localhost"
    /// - Port: 8086
    /// - Bucket: "bucket"
    /// - Token: "token"
    ///
    /// # Returns
    ///
    /// `true` if the key was recognized as an InfluxDB configuration key and processed,
    /// `false` if the key is not related to InfluxDB configuration.
    fn fill_influx<T>(
        &self,
        cfg: &mut Configs<T>,
        key: impl Into<std::string::String>,
        value: impl Into<std::string::String>,
    ) -> bool
    where
        T: DynamicConfigs,
    {
        match key.into().as_str() {
            INFLUX_HOST_ENV_KEY => {
                cfg.influx.host = self.get_from_secret(value.into(), "http://localhost".into());
                true
            }
            INFLUX_PORT_ENV_KEY => {
                cfg.influx.port = self.get_from_secret(value.into(), 8086);
                true
            }
            INFLUX_BUCKET_ENV_KEY => {
                cfg.influx.bucket = self.get_from_secret(value.into(), "bucket".into());
                true
            }
            INFLUX_TOKEN_ENV_KEY => {
                cfg.influx.token = self.get_from_secret(value.into(), "token".into());
                true
            }
            _ => false,
        }
    }
}

// Helper methods
impl ConfigBuilder {
    /// Retrieves a value from the secret manager or parses it directly.
    ///
    /// This method handles both plain values and secrets, providing a unified interface
    /// for configuration value retrieval. When a value is prefixed with the secret
    /// prefix (defined in `SECRET_PREFIX`), it's treated as a key to look up in the
    /// configured secret manager. Otherwise, it's parsed directly.
    ///
    /// The method includes fallback mechanisms to ensure configuration robustness:
    /// - If parsing a direct value fails, the default value is returned
    /// - If a secret key isn't found in the secret manager, the default value is returned
    /// - If parsing a secret value fails, the default value is returned with an error log
    ///
    /// # Type Parameters
    ///
    /// * `T` - The type to parse the value into, must implement `FromStr`
    ///
    /// # Parameters
    ///
    /// * `key` - The value to process, either a plain value to parse or a secret key
    ///   (prefixed with `SECRET_PREFIX`) to look up in the secret manager
    /// * `default` - The default value to return if parsing fails or the secret isn't found
    ///
    /// # Returns
    ///
    /// The parsed value from the direct input or from the secret manager, or the default
    /// value if either retrieval or parsing fails.
    ///
    /// # Examples
    ///
    /// ```
    /// // Direct parsing of a value
    /// let port = self.get_from_secret("8080".to_string(), 9000);  // Returns 8080 as i32
    ///
    /// // Retrieving and parsing a secret (assuming SECRET_PREFIX is "!")
    /// let password = self.get_from_secret("!my_password_key".to_string(), "default");
    /// // Returns the value of "my_password_key" from the secret manager
    /// ```
    fn get_from_secret<T>(&self, key: String, default: T) -> T
    where
        T: FromStr,
    {
        if !key.starts_with(SECRET_PREFIX) {
            return key.parse().unwrap_or(default);
        }

        let Ok(v) = self.client.clone().unwrap().get_by_key(&key) else {
            error!(key = key, "secret key was not found");
            return default;
        };

        v.parse().unwrap_or_else(|_| {
            error!(key = key, value = v, "parse went wrong");
            default
        })
    }

    /// Decodes a base64-encoded string into a UTF-8 string.
    ///
    /// This method performs a two-step decoding process:
    /// 1. Decodes the base64-encoded input into raw bytes
    /// 2. Converts the raw bytes into a UTF-8 string
    ///
    /// Both steps include error handling with logging to help diagnose issues.
    /// The underscore prefix in the method name indicates it's intended for internal use.
    ///
    /// # Parameters
    ///
    /// * `text` - Base64-encoded string to decode
    ///
    /// # Returns
    ///
    /// A `Result<String, ()>` containing:
    /// - `Ok(String)` with the decoded UTF-8 string on success
    /// - `Err(())` with logged error details on failure
    ///
    /// # Errors
    ///
    /// This method can fail in two ways:
    /// - If the input isn't valid base64 (logged as "base64 decoded error")
    /// - If the decoded bytes aren't valid UTF-8 (logged as "error to convert to String")
    fn _decoded(&self, text: String) -> Result<String, ()> {
        let d = match general_purpose::STANDARD.decode(text) {
            Err(err) => {
                error!(error = err.to_string(), "base64 decoded error");
                Err(())
            }
            Ok(v) => Ok(v),
        }?;

        match String::from_utf8(d) {
            Err(err) => {
                error!(error = err.to_string(), "error to convert to String");
                Err(())
            }
            Ok(s) => Ok(s),
        }
    }
}
