use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminConfig {
    pub cluster_endpoint: String,
    pub admin_token: String,
    pub timeout_millis: u64,
    pub default_namespace: String,
    pub output_format: OutputFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutputFormat {
    Table,
    Json,
    Yaml,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            cluster_endpoint: "http://127.0.0.1:9090".to_string(),
            admin_token: "noesis-admin-master-key".to_string(),
            timeout_millis: 5000,
            default_namespace: "production".to_string(),
            output_format: OutputFormat::Table,
        }
    }
}
