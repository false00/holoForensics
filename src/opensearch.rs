#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use anyhow::{Context, Result, anyhow};
use chrono::Utc;
use regex::Regex;
use reqwest::blocking::Client;
use serde::Deserialize;
use serde_json::{Map, Value};

#[derive(Debug, Clone)]
pub struct Config {
    pub url: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub index: String,
    pub insecure: bool,
    pub batch_size: usize,
}

#[derive(Debug, Clone)]
pub struct OpenSearchClient {
    pub client: Client,
    pub config: Config,
}

#[derive(Debug, Clone)]
pub struct ExportMetadata {
    pub parser: String,
    pub artifact: String,
    pub input_zip: String,
}

#[derive(Debug, Deserialize)]
struct BulkResponse {
    errors: bool,
    items: Vec<BTreeMap<String, BulkItemStatus>>,
}

#[derive(Debug, Deserialize)]
struct BulkItemStatus {
    status: u16,
    error: Option<Value>,
}

impl OpenSearchClient {
    pub fn new(config: Config) -> Result<Self> {
        if config.url.trim().is_empty() {
            return Err(anyhow!("opensearch url is required"));
        }
        if config.index.trim().is_empty() {
            return Err(anyhow!("opensearch index is required"));
        }

        let client = Client::builder()
            .danger_accept_invalid_certs(config.insecure)
            .build()
            .context("build OpenSearch HTTP client")?;

        Ok(Self { client, config })
    }

    pub fn base_url(&self) -> &str {
        &self.config.url
    }

    pub fn index(&self) -> &str {
        &self.config.index
    }

    pub fn index_jsonl_file(&self, path: &Path, metadata: &ExportMetadata) -> Result<usize> {
        let file = File::open(path).with_context(|| format!("open jsonl {}", path.display()))?;
        let reader = BufReader::new(file);

        let mut indexed = 0usize;
        let mut batch_count = 0usize;
        let mut payload = String::new();

        for line in reader.lines() {
            let line = line?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            let mut document: Map<String, Value> = serde_json::from_str(trimmed)
                .with_context(|| format!("decode {}", path.display()))?;
            document.insert(
                "holo_forensics_parser".to_string(),
                Value::String(metadata.parser.clone()),
            );
            document.insert(
                "holo_forensics_artifact".to_string(),
                Value::String(metadata.artifact.clone()),
            );
            document.insert(
                "holo_forensics_input_zip".to_string(),
                Value::String(metadata.input_zip.clone()),
            );
            document.insert(
                "holo_forensics_output_file".to_string(),
                Value::String(
                    path.file_name()
                        .and_then(|value| value.to_str())
                        .unwrap_or_default()
                        .to_string(),
                ),
            );

            payload.push_str("{\"index\":{}}\n");
            payload.push_str(&serde_json::to_string(&Value::Object(document))?);
            payload.push('\n');
            batch_count += 1;

            if batch_count >= self.config.batch_size.max(1) {
                indexed += self.send_bulk(&payload)?;
                payload.clear();
                batch_count = 0;
            }
        }

        if batch_count > 0 {
            indexed += self.send_bulk(&payload)?;
        }

        Ok(indexed)
    }

    pub fn refresh(&self) -> Result<()> {
        let request = self.client.post(self.endpoint_url("_refresh"));
        let request = match (&self.config.username, &self.config.password) {
            (Some(username), Some(password)) => request.basic_auth(username, Some(password)),
            _ => request,
        };

        let response = request.send().context("refresh OpenSearch index")?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            return Err(anyhow!("refresh {status}: {}", body.trim()));
        }
        Ok(())
    }

    fn send_bulk(&self, payload: &str) -> Result<usize> {
        let request = self
            .client
            .post(self.endpoint_url("_bulk"))
            .header("Content-Type", "application/x-ndjson")
            .header("Accept", "application/json")
            .body(payload.to_string());
        let request = match (&self.config.username, &self.config.password) {
            (Some(username), Some(password)) => request.basic_auth(username, Some(password)),
            _ => request,
        };

        let response = request.send().context("send OpenSearch bulk request")?;
        let status = response.status();
        let body = response.text().context("read OpenSearch bulk response")?;
        if !status.is_success() {
            return Err(anyhow!("bulk {status}: {}", body.trim()));
        }

        let decoded: BulkResponse =
            serde_json::from_str(&body).context("decode OpenSearch bulk response")?;
        let mut successful = 0usize;
        for item in decoded.items {
            for status in item.into_values() {
                if (200..300).contains(&status.status) {
                    successful += 1;
                    continue;
                }

                return Err(anyhow!(
                    "bulk item failed with status {}{}",
                    status.status,
                    status
                        .error
                        .map(|error| format!(": {}", error))
                        .unwrap_or_default()
                ));
            }
        }

        if decoded.errors {
            return Err(anyhow!("bulk response reported errors"));
        }

        Ok(successful)
    }

    fn endpoint_url(&self, suffix: &str) -> String {
        format!(
            "{}/{}/{}",
            self.config.url.trim_end_matches('/'),
            self.config.index,
            suffix
        )
    }
}

pub fn default_index_name(parse_mode: &str, collection_name: &str) -> String {
    let timestamp = Utc::now().format("%Y%m%d-%H%M%S");
    format!(
        "l2t-{}-{}-{}",
        sanitize(parse_mode),
        sanitize(collection_name),
        timestamp
    )
}

pub fn build_url(host: Option<&str>, port: Option<&str>) -> Result<Option<String>> {
    let Some(host) = host.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };

    if host.contains("://") {
        return Ok(Some(host.trim_end_matches('/').to_string()));
    }

    let mut url = format!("http://{host}");
    if let Some(port) = port.map(str::trim).filter(|value| !value.is_empty()) {
        url.push(':');
        url.push_str(port);
    }
    Ok(Some(url))
}

fn sanitize(value: &str) -> String {
    let lowered = value.trim().to_lowercase().replace([' ', '_', '.'], "-");
    let collapsed = Regex::new(r"[^a-z0-9-]+")
        .expect("valid regex")
        .replace_all(&lowered, "-")
        .to_string();
    let trimmed = collapsed.trim_matches('-').to_string();
    if trimmed.is_empty() {
        "run".to_string()
    } else {
        trimmed
    }
}

#[cfg(test)]
mod tests {
    use super::{build_url, default_index_name};

    #[test]
    fn build_url_returns_none_when_host_missing() {
        assert_eq!(build_url(None, Some("9200")).unwrap(), None);
        assert_eq!(build_url(Some("   "), Some("9200")).unwrap(), None);
    }

    #[test]
    fn build_url_preserves_explicit_scheme() {
        assert_eq!(
            build_url(Some("https://search.example:9200/"), Some("443")).unwrap(),
            Some("https://search.example:9200".to_string())
        );
    }

    #[test]
    fn build_url_constructs_http_url() {
        assert_eq!(
            build_url(Some("127.0.0.1"), Some("9200")).unwrap(),
            Some("http://127.0.0.1:9200".to_string())
        );
        assert_eq!(
            build_url(Some("search.internal"), None).unwrap(),
            Some("http://search.internal".to_string())
        );
    }

    #[test]
    fn default_index_name_sanitizes_components() {
        let generated = default_index_name("Full Mode", "Case_123.zip");
        assert!(generated.starts_with("l2t-full-mode-case-123-zip-"));
    }
}
