// Copyright (c) 2025, The Ruskit Authors
// MIT License
// All rights reserved.

//! # Configuration Builder
//!
//! This module provides the main `ConfigBuilder` implementation which is responsible for
//! building application configurations from environment variables and secret managers.
//!
//! The builder follows a fluent interface pattern, allowing users to selectively enable
//! different configuration sections based on their application's needs.

use crate::{
    env_keys::{
        APP_NAME_ENV_KEY, APP_PORT_ENV_KEY, AWS_DEFAULT_REGION, AWS_IAM_ACCESS_KEY_ID,
        AWS_IAM_SECRET_ACCESS_KEY, DEV_ENV_FILE_NAME, DYNAMO_ENDPOINT_ENV_KEY,
        DYNAMO_EXPIRE_ENV_KEY, DYNAMO_REGION_ENV_KEY, DYNAMO_TABLE_ENV_KEY,
        ENABLE_HEALTH_READINESS_ENV_KEY, ENABLE_METRICS_ENV_KEY, ENABLE_TRACES_ENV_KEY,
        HEALTH_READINESS_PORT_ENV_KEY, HOST_NAME_ENV_KEY, IDENTITY_SERVER_AUDIENCE_ENV_KEY,
        IDENTITY_SERVER_CLIENT_ID_ENV_KEY, IDENTITY_SERVER_CLIENT_SECRET_ENV_KEY,
        IDENTITY_SERVER_GRANT_TYPE_ENV_KEY, IDENTITY_SERVER_ISSUER_ENV_KEY,
        IDENTITY_SERVER_REALM_ENV_KEY, IDENTITY_SERVER_URL_ENV_KEY, INFLUX_BUCKET_ENV_KEY,
        INFLUX_HOST_ENV_KEY, INFLUX_PORT_ENV_KEY, INFLUX_TOKEN_ENV_KEY, KAFKA_CA_PATH_KEY,
        KAFKA_CERTIFICATE_PATH_KEY, KAFKA_ENDPOINT_IDENTIFICATION_ALGORITHM_KEY,
        KAFKA_HOST_ENV_KEY, KAFKA_KEY_STORE_PASSWORD_KEY, KAFKA_KEY_STORE_PATH_KEY,
        KAFKA_PASSWORD_ENV_KEY, KAFKA_PORT_ENV_KEY, KAFKA_SASL_MECHANISMS_ENV_KEY,
        KAFKA_SECURITY_PROTOCOL_ENV_KEY, KAFKA_TIMEOUT_ENV_KEY, KAFKA_TRUST_STORE_PASSWORD_KEY,
        KAFKA_TRUST_STORE_PATH_KEY, KAFKA_USER_ENV_KEY, LOCAL_ENV_FILE_NAME, LOG_LEVEL_ENV_KEY,
        METRIC_ACCESS_KEY_ENV_KEY, METRIC_EXPORT_RATE_BASE_ENV_KEY, METRIC_EXPORT_TIMEOUT_ENV_KEY,
        METRIC_EXPORTER_ENV_KEY, METRIC_HEADER_ACCESS_KEY_ENV_KEY, METRIC_HOST_ENV_KEY,
        METRIC_SERVICE_TYPE_ENV_KEY, MQTT_BROKER_KIND_ENV_KEY, MQTT_BROKERS_ENV_KEY,
        MQTT_CA_CERT_PATH_ENV_KEY, MQTT_HOST_ENV_KEY, MQTT_MULTI_BROKER_ENABLED_ENV_KEY,
        MQTT_PASSWORD_ENV_KEY, MQTT_PORT_ENV_KEY, MQTT_TRANSPORT_ENV_KEY, MQTT_USER_ENV_KEY,
        POSTGRES_CA_PATH_ENV_KEY, POSTGRES_DB_ENV_KEY, POSTGRES_HOST_ENV_KEY,
        POSTGRES_PASSWORD_ENV_KEY, POSTGRES_PORT_ENV_KEY, POSTGRES_SSL_MODE_ENV_KEY,
        POSTGRES_USER_ENV_KEY, PROD_FILE_NAME, RABBITMQ_HOST_ENV_KEY, RABBITMQ_PASSWORD_ENV_KEY,
        RABBITMQ_PORT_ENV_KEY, RABBITMQ_USER_ENV_KEY, RABBITMQ_VHOST_ENV_KEY, SECRET_KEY_ENV_KEY,
        SECRET_MANAGER_ENV_KEY, SECRET_PREFIX, SQLITE_FILE_NAME_ENV_KEY, STAGING_FILE_NAME,
        TRACE_ACCESS_KEY_ENV_KEY, TRACE_EXPORT_RATE_BASE_ENV_KEY, TRACE_EXPORT_TIMEOUT_ENV_KEY,
        TRACE_EXPORTER_ENV_KEY, TRACE_HEADER_ACCESS_KEY_ENV_KEY, TRACE_HOST_ENV_KEY,
        TRACE_SERVICE_TYPE_ENV_KEY,
    },
    errors::ConfigsError,
};
use base64::{Engine, engine::general_purpose};
use configs::{
    AppConfigs, Configs, DynamicConfigs, Environment, MQTTBrokerKind, MQTTConnectionConfigs,
    MQTTTransport, MetricExporterKind, SecretsManagerKind, TraceExporterKind,
};
use dotenvy::from_filename;
use secrets_manager::{AWSSecretClientBuilder, FakeSecretClient, SecretClient};
use std::{env, str::FromStr, sync::Arc};
use tracing::error;

/// The main configuration builder struct.
///
/// `ConfigBuilder` provides a fluent interface for building application configurations
/// from environment variables and secret managers. By default, all configuration sections
/// are disabled and must be explicitly enabled through the builder methods.
///
/// # Example
///
/// ```rust
/// let config_builder = ConfigBuilder::new()
///     .postgres()
///     .mqtt()
///     .trace();
///
/// let configs = config_builder.build::<MyDynamicConfigs>().await?;
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
    metric: bool,
    trace: bool,
    health: bool,
    identity: bool,
}

impl ConfigBuilder {
    /// Creates a new instance of the `ConfigBuilder`.
    ///
    /// By default, all configuration sections are disabled.
    pub fn new() -> ConfigBuilder {
        ConfigBuilder::default()
    }

    /// Enables MQTT configuration.
    ///
    /// When enabled, the builder will attempt to load MQTT-related configuration from
    /// environment variables.
    pub fn mqtt(mut self) -> Self {
        self.mqtt = true;
        self
    }

    /// Enables RabbitMQ configuration.
    ///
    /// When enabled, the builder will attempt to load RabbitMQ-related configuration
    /// from environment variables.
    pub fn rabbitmq(mut self) -> Self {
        self.rabbitmq = true;
        self
    }

    /// Enables Kafka configuration.
    ///
    /// When enabled, the builder will attempt to load Kafka-related configuration
    /// from environment variables.
    pub fn kafka(mut self) -> Self {
        self.kafka = true;
        self
    }

    /// Enables PostgreSQL configuration.
    ///
    /// When enabled, the builder will attempt to load PostgreSQL-related configuration
    /// from environment variables.
    pub fn postgres(mut self) -> Self {
        self.postgres = true;
        self
    }

    /// Enables SQLite configuration.
    ///
    /// When enabled, the builder will attempt to load SQLite-related configuration
    /// from environment variables.
    pub fn sqlite(mut self) -> Self {
        self.sqlite = true;
        self
    }

    /// Enables DynamoDB configuration.
    ///
    /// When enabled, the builder will attempt to load DynamoDB-related configuration
    /// from environment variables.
    pub fn dynamodb(mut self) -> Self {
        self.dynamo = true;
        self
    }

    /// Enables InfluxDB configuration.
    ///
    /// When enabled, the builder will attempt to load InfluxDB-related configuration
    /// from environment variables.
    pub fn influx(mut self) -> Self {
        self.influx = true;
        self
    }

    /// Enables AWS configuration.
    ///
    /// When enabled, the builder will attempt to load AWS-related configuration
    /// from environment variables.
    pub fn aws(mut self) -> Self {
        self.aws = true;
        self
    }

    /// Enables metrics configuration.
    ///
    /// When enabled, the builder will attempt to load metrics-related configuration
    /// from environment variables.
    pub fn metric(mut self) -> Self {
        self.metric = true;
        self
    }

    /// Enables tracing configuration.
    ///
    /// When enabled, the builder will attempt to load tracing-related configuration
    /// from environment variables.
    pub fn trace(mut self) -> Self {
        self.trace = true;
        self
    }

    /// Enables health and readiness check configuration.
    ///
    /// When enabled, the builder will attempt to load health check-related configuration
    /// from environment variables.
    pub fn health(mut self) -> Self {
        self.health = true;
        self
    }

    /// Enables identity server configuration.
    ///
    /// When enabled, the builder will attempt to load identity server-related configuration
    /// from environment variables.
    pub fn identity_server(mut self) -> Self {
        self.identity = true;
        self
    }

    /// Builds the configuration based on the enabled configuration sections.
    ///
    /// This method loads environment variables from the appropriate .env file based on
    /// the application environment, sets up the secret manager client, and populates
    /// the configuration struct with values from environment variables and secrets.
    ///
    /// # Type Parameters
    ///
    /// * `T` - A type that implements the `DynamicConfigs` trait for application-specific
    ///         dynamic configuration.
    ///
    /// # Returns
    ///
    /// A `Result` containing the populated `Configs<T>` struct or a `ConfigsError` if
    /// configuration building fails.
    pub async fn build<'c, T>(&mut self) -> Result<Configs<T>, ConfigsError>
    where
        T: DynamicConfigs,
    {
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

        let mut cfg = Configs::<T>::default();
        self.fill_app(&mut cfg);

        match logging::setup(&cfg.app) {
            Err(_) => Err(ConfigsError::InternalError {}),
            _ => Ok(()),
        }?;

        cfg.dynamic.load();

        self.client = self.get_secret_client(&cfg.app).await?;

        for (key, value) in env::vars() {
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
            if self.fill_trace(&mut cfg, &key, &value) {
                continue;
            }
            if self.fill_metric(&mut cfg, &key, &value) {
                continue;
            }
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

        Ok(cfg)
    }
}

// Secret client implementation
impl ConfigBuilder {
    /// Creates and returns a secret client based on the application configuration.
    ///
    /// # Parameters
    ///
    /// * `app_cfg` - Application configuration containing secret manager settings.
    ///
    /// # Returns
    ///
    /// A `Result` containing an optional secret client wrapped in an `Arc` or a
    /// `ConfigsError` if secret client creation fails.
    async fn get_secret_client(
        &self,
        app_cfg: &AppConfigs,
    ) -> Result<Option<Arc<dyn SecretClient>>, ConfigsError> {
        match app_cfg.secret_manager {
            SecretsManagerKind::None => Ok(Some(Arc::new(FakeSecretClient::new()))),

            SecretsManagerKind::AWSSecretManager => {
                let secret_key = env::var(SECRET_KEY_ENV_KEY).unwrap_or_default();

                match AWSSecretClientBuilder::new(secret_key).build().await {
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
    /// Fills the core application configuration from environment variables.
    ///
    /// # Parameters
    ///
    /// * `cfg` - Mutable reference to the configuration being built.
    fn fill_app<T>(&self, cfg: &mut Configs<T>)
    where
        T: DynamicConfigs,
    {
        let env = Environment::from_rust_env();
        let name = self.fmt_name(&env, env::var(APP_NAME_ENV_KEY).unwrap_or_default());
        let secret_key = env::var(SECRET_KEY_ENV_KEY).unwrap_or_default();
        let host = env::var(HOST_NAME_ENV_KEY).unwrap_or_default();
        let port = env::var(APP_PORT_ENV_KEY)
            .unwrap_or("3000".into())
            .parse()
            .unwrap_or_default();
        let log_level = env::var(LOG_LEVEL_ENV_KEY).unwrap_or("debug".into());
        let secret_manager = env::var(SECRET_MANAGER_ENV_KEY).unwrap_or("None".into());

        cfg.app = AppConfigs {
            enable_external_creates_logging: false,
            env,
            host,
            log_level,
            name,
            port,
            secret_key,
            secret_manager: SecretsManagerKind::from(&secret_manager),
        };
    }

    /// Fills metric configuration from environment variables.
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
    fn fill_metric<T>(
        &self,
        cfg: &mut Configs<T>,
        key: impl Into<std::string::String>,
        value: impl Into<std::string::String>,
    ) -> bool
    where
        T: DynamicConfigs,
    {
        if !self.metric {
            return false;
        }

        match key.into().as_str() {
            ENABLE_METRICS_ENV_KEY => {
                cfg.metric.enable = self.get_from_secret(value.into(), false);
                true
            }
            METRIC_EXPORTER_ENV_KEY => {
                cfg.metric.exporter =
                    self.get_from_secret(value.into(), MetricExporterKind::Stdout);
                true
            }
            METRIC_HOST_ENV_KEY => {
                cfg.metric.host = self.get_from_secret(value.into(), "localhost".into());
                true
            }
            METRIC_HEADER_ACCESS_KEY_ENV_KEY => {
                cfg.metric.header_access_key = self.get_from_secret(value.into(), "api-key".into());
                true
            }
            METRIC_ACCESS_KEY_ENV_KEY => {
                cfg.metric.access_key = self.get_from_secret(value.into(), "key".into());
                true
            }
            METRIC_SERVICE_TYPE_ENV_KEY => {
                cfg.metric.service_type = self.get_from_secret(value.into(), "service".into());
                true
            }
            METRIC_EXPORT_TIMEOUT_ENV_KEY => {
                let k: String = value.into();
                cfg.metric.export_timeout = self.get_from_secret(k.clone(), 30);
                true
            }
            METRIC_EXPORT_RATE_BASE_ENV_KEY => {
                cfg.metric.export_rate_base = self.get_from_secret(value.into(), 0.8);
                true
            }
            _ => false,
        }
    }

    /// Fills tracing configuration from environment variables.
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
    fn fill_trace<T>(
        &self,
        cfg: &mut Configs<T>,
        key: impl Into<std::string::String>,
        value: impl Into<std::string::String>,
    ) -> bool
    where
        T: DynamicConfigs,
    {
        if !self.trace {
            return false;
        }

        match key.into().as_str() {
            ENABLE_TRACES_ENV_KEY => {
                cfg.trace.enable = self.get_from_secret(value.into(), false);
                true
            }
            TRACE_EXPORTER_ENV_KEY => {
                cfg.trace.exporter = self.get_from_secret(value.into(), TraceExporterKind::Stdout);
                true
            }
            TRACE_HOST_ENV_KEY => {
                cfg.trace.host = self.get_from_secret(value.into(), "localhost".into());
                true
            }
            TRACE_HEADER_ACCESS_KEY_ENV_KEY => {
                cfg.trace.header_access_key = self.get_from_secret(value.into(), "api-key".into());
                true
            }
            TRACE_ACCESS_KEY_ENV_KEY => {
                cfg.trace.access_key = self.get_from_secret(value.into(), "key".into());
                true
            }
            TRACE_SERVICE_TYPE_ENV_KEY => {
                cfg.trace.service_type = self.get_from_secret(value.into(), "service".into());
                true
            }
            TRACE_EXPORT_TIMEOUT_ENV_KEY => {
                let k: String = value.into();
                cfg.trace.export_timeout = self.get_from_secret(k.clone(), 30);
                true
            }
            TRACE_EXPORT_RATE_BASE_ENV_KEY => {
                cfg.trace.export_rate_base = self.get_from_secret(value.into(), 0.8);
                true
            }
            _ => false,
        }
    }

    /// Fills identity server configuration from environment variables.
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
    /// # Parameters
    ///
    /// * `cfg` - Mutable reference to the configuration being built.
    /// * `key` - Environment variable key.
    /// * `value` - Environment variable value.
    ///
    /// # Returns
    ///
    /// `true` if the key was recognized and processed, `false` otherwise.
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
    /// # Parameters
    ///
    /// * `cfg` - Mutable reference to the configuration being built.
    /// * `key` - Environment variable key.
    /// * `value` - Environment variable value.
    ///
    /// # Returns
    ///
    /// `true` if the key was recognized and processed, `false` otherwise.
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
    /// # Parameters
    ///
    /// * `cfg` - Mutable reference to the configuration being built.
    /// * `key` - Environment variable key.
    /// * `value` - Environment variable value.
    ///
    /// # Returns
    ///
    /// `true` if the key was recognized and processed, `false` otherwise.
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
    /// # Parameters
    ///
    /// * `cfg` - Mutable reference to the configuration being built.
    /// * `key` - Environment variable key.
    /// * `value` - Environment variable value.
    ///
    /// # Returns
    ///
    /// `true` if the key was recognized and processed, `false` otherwise.
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
    /// # Parameters
    ///
    /// * `cfg` - Mutable reference to the configuration being built.
    /// * `key` - Environment variable key.
    /// * `value` - Environment variable value.
    ///
    /// # Returns
    ///
    /// `true` if the key was recognized and processed, `false` otherwise.
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
    /// # Parameters
    ///
    /// * `cfg` - Mutable reference to the configuration being built.
    /// * `key` - Environment variable key.
    /// * `value` - Environment variable value.
    ///
    /// # Returns
    ///
    /// `true` if the key was recognized and processed, `false` otherwise.
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
    /// # Parameters
    ///
    /// * `cfg` - Mutable reference to the configuration being built.
    /// * `key` - Environment variable key.
    /// * `value` - Environment variable value.
    ///
    /// # Returns
    ///
    /// `true` if the key was recognized and processed, `false` otherwise.
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
            "SQLITE_USER" => {
                cfg.sqlite.user = self.get_from_secret(value.into(), "user".into());
                true
            }
            "SQLITE_PASSWORD" => {
                cfg.sqlite.password = self.get_from_secret(value.into(), "password".into());
                true
            }
            _ => false,
        }
    }

    /// Fills InfluxDB configuration from environment variables.
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
    /// Retrieves a value from the secret manager or returns the default value.
    ///
    /// # Parameters
    ///
    /// * `key` - Secret key or plain value.
    /// * `default` - Default value to return if the key is not found or parsing fails.
    ///
    /// # Returns
    ///
    /// The parsed value or the default value.
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

    /// Formats the application name based on the environment.
    ///
    /// # Parameters
    ///
    /// * `env` - Application environment.
    /// * `name` - Application name.
    ///
    /// # Returns
    ///
    /// The formatted application name.
    fn fmt_name(&self, env: &Environment, name: String) -> String {
        let env_str = env.to_string();
        if name.starts_with(&env_str) {
            return name;
        }

        format!("{}-{}", env_str, name)
    }

    /// Decodes a base64-encoded string.
    ///
    /// # Parameters
    ///
    /// * `text` - Base64-encoded string.
    ///
    /// # Returns
    ///
    /// A `Result` containing the decoded string or an error.
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
