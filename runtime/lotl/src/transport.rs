//! JOCKEY Evidence Transport Adapter
//!
//! Provides a pluggable transport layer for delivering forensic evidence bundles
//! from field agents to the central JOCKEY management interface, and for
//! receiving commands from the server.
//!
//! ## Transport Variants
//!
//! ### 1. Direct HTTP (`TransportKind::Direct`)
//! Standard HTTPS POST to a known JOCKEY server URL. Used in controlled
//! lab environments where network monitoring is not a concern.
//!
//! ### 2. Domain Fronting (`TransportKind::DomainFronted`)
//! Routes traffic through a trusted CDN (e.g. Cloudflare, CloudFront, Fastly).
//! The TLS SNI and outer `Host` header use a trusted CDN domain, while the
//! `X-Forwarded-Host` or inner HTTP/2 `:authority` pseudo-header specifies
//! the actual JOCKEY server. The CDN then forwards the request internally.
//!
//! This makes the network traffic indistinguishable from legitimate CDN
//! traffic to a network-layer IDS/DLP that inspects only the SNI.
//!
//! ```text
//! Field Agent ──TLS SNI: cloudflare.com──▶ CDN edge ──internal──▶ JOCKEY API
//!              Host: cloudflare.com
//!              X-Jockey-Target: jockey.your-domain.com
//! ```
//!
//! ### 3. Cloud API Relay (`TransportKind::CloudApiRelay`)
//! Evidence is uploaded to a cloud storage bucket (AWS S3, Google Cloud
//! Storage, Azure Blob) via presigned URL — no cloud SDK IAT imports required,
//! just plain HTTPS PUT. Commands are polled from a message queue (SQS, Pub/Sub)
//! via presigned GET URL. Traffic appears as legitimate cloud storage I/O.
//!
//! ## DSL Integration
//!
//! The transport is configured in the JOCKEY `.jy` source file's `config {}` block:
//!
//! ```jockey
//! config {
//!     transport = "domain_fronted"
//!     cdn_host   = "cloudflare.com"
//!     relay_url  = "https://jockey.your-domain.com"
//! }
//! ```

use serde::{Deserialize, Serialize};

/// Transport configuration loaded from a `.jy` file's `config {}` block or
/// provided programmatically by the CLI/API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportConfig {
    /// Which transport variant to use.
    pub kind: TransportKind,
    /// The actual JOCKEY server URL (used for Direct and DomainFronted).
    pub relay_url: String,
    /// CDN hostname used as the TLS SNI and outer `Host` for domain fronting.
    /// Ignored when `kind != DomainFronted`.
    pub cdn_host: Option<String>,
    /// Presigned upload URL for evidence delivery (CloudApiRelay).
    pub upload_presigned_url: Option<String>,
    /// Presigned poll URL for command retrieval (CloudApiRelay).
    pub poll_presigned_url: Option<String>,
    /// Cloud provider name for logging purposes.
    pub cloud_provider: Option<CloudProvider>,
    /// Maximum bytes per upload chunk (default 4 MB).
    pub chunk_size_bytes: usize,
    /// TLS CA bundle path (None = system default).
    pub ca_bundle: Option<std::path::PathBuf>,
    /// Connection timeout in seconds.
    pub timeout_secs: u64,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            kind: TransportKind::Direct,
            relay_url: "http://localhost:8080".to_string(),
            cdn_host: None,
            upload_presigned_url: None,
            poll_presigned_url: None,
            cloud_provider: None,
            chunk_size_bytes: 4 * 1024 * 1024,
            ca_bundle: None,
            timeout_secs: 30,
        }
    }
}

/// The transport variant selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TransportKind {
    /// Plain HTTPS to the JOCKEY API server.
    #[default]
    Direct,
    /// Domain-fronted HTTPS via a CDN edge node.
    DomainFronted,
    /// Cloud storage presigned URL relay (S3, GCS, Azure Blob, etc.).
    CloudApiRelay,
}

impl std::str::FromStr for TransportKind {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "direct" => Ok(TransportKind::Direct),
            "domain_fronted" | "domain-fronted" | "cdn" => Ok(TransportKind::DomainFronted),
            "cloud_api_relay" | "cloud-api-relay" | "cloud" | "s3" | "gcs" => {
                Ok(TransportKind::CloudApiRelay)
            }
            other => Err(format!(
                "Unknown transport kind '{}'. Valid values: direct, domain_fronted, cloud_api_relay",
                other
            )),
        }
    }
}

/// Supported cloud storage providers for the relay transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudProvider {
    AwsS3,
    GoogleCloudStorage,
    AzureBlob,
    Generic,
}

/// Result of a transport operation.
#[derive(Debug, Serialize)]
pub struct TransportResult {
    pub success: bool,
    pub bytes_transferred: usize,
    pub response_code: Option<u16>,
    pub transport_kind: TransportKind,
    pub note: String,
}

/// The transport adapter trait.
///
/// Implementations are responsible for delivering an evidence JSON bundle
/// (as raw bytes) to the JOCKEY server and for retrieving pending commands.
pub trait EvidenceTransport: Send + Sync {
    /// Deliver evidence bytes to the configured destination.
    fn deliver_evidence(
        &self,
        investigation_name: &str,
        evidence_bytes: &[u8],
    ) -> Result<TransportResult, TransportError>;

    /// Poll for a pending command from the server (if any).
    /// Returns `Ok(None)` if no command is pending.
    fn poll_command(&self) -> Result<Option<String>, TransportError>;

    /// Human-readable description of this transport for logging.
    fn describe(&self) -> String;
}

/// Errors from the transport layer.
#[derive(Debug, thiserror::Error, Serialize)]
pub enum TransportError {
    #[error("Transport I/O error: {0}")]
    Io(String),
    #[error("HTTP error {status}: {body}")]
    Http { status: u16, body: String },
    #[error("Domain fronting configuration error: {0}")]
    Config(String),
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Transport not supported on this platform: {0}")]
    NotSupported(String),
}

// ────────────────────────────────────────────────────────────────────────────
// 1. Direct HTTP Transport
// ────────────────────────────────────────────────────────────────────────────

/// Delivers evidence via a plain HTTPS POST to the JOCKEY API.
pub struct DirectTransport {
    config: TransportConfig,
}

impl DirectTransport {
    pub fn new(config: TransportConfig) -> Self {
        Self { config }
    }
}

impl EvidenceTransport for DirectTransport {
    fn deliver_evidence(
        &self,
        investigation_name: &str,
        evidence_bytes: &[u8],
    ) -> Result<TransportResult, TransportError> {
        let url = format!(
            "{}/api/evidence/ingest/{}",
            self.config.relay_url.trim_end_matches('/'),
            investigation_name
        );

        deliver_via_http(
            &url,
            None,  // no custom Host override
            None,  // no X-Jockey-Target header
            evidence_bytes,
            self.config.timeout_secs,
            TransportKind::Direct,
        )
    }

    fn poll_command(&self) -> Result<Option<String>, TransportError> {
        // Direct HTTP: GET /api/commands/poll
        Ok(None) // Simplified stub
    }

    fn describe(&self) -> String {
        format!("DirectTransport -> {}", self.config.relay_url)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// 2. Domain-Fronted Transport
// ────────────────────────────────────────────────────────────────────────────

/// Delivers evidence via domain-fronted HTTPS.
///
/// The TLS handshake SNI and the outer HTTP `Host` header are set to the CDN
/// hostname (`cdn_host`), making the connection look like traffic to a trusted
/// CDN. A custom header (`X-Jockey-Target`) carries the real destination, which
/// the CDN's origin rules forward to internally.
pub struct DomainFrontedTransport {
    config: TransportConfig,
}

impl DomainFrontedTransport {
    pub fn new(config: TransportConfig) -> Result<Self, TransportError> {
        if config.cdn_host.is_none() {
            return Err(TransportError::Config(
                "DomainFrontedTransport requires cdn_host to be set in the transport config"
                    .to_string(),
            ));
        }
        if config.relay_url.is_empty() {
            return Err(TransportError::Config(
                "DomainFrontedTransport requires relay_url (the real JOCKEY server) to be set"
                    .to_string(),
            ));
        }
        Ok(Self { config })
    }
}

impl EvidenceTransport for DomainFrontedTransport {
    fn deliver_evidence(
        &self,
        investigation_name: &str,
        evidence_bytes: &[u8],
    ) -> Result<TransportResult, TransportError> {
        let cdn_host = self.config.cdn_host.as_deref().unwrap_or("");
        let real_target = self.config.relay_url.trim_end_matches('/');

        // The URL we connect to uses the CDN hostname so the TLS SNI matches
        let cdn_url = format!("https://{}/api/evidence/ingest/{}", cdn_host, investigation_name);

        deliver_via_http(
            &cdn_url,
            Some(cdn_host),    // Override HTTP Host header to CDN host
            Some(real_target), // Pass real server via custom header
            evidence_bytes,
            self.config.timeout_secs,
            TransportKind::DomainFronted,
        )
    }

    fn poll_command(&self) -> Result<Option<String>, TransportError> {
        Ok(None)
    }

    fn describe(&self) -> String {
        format!(
            "DomainFrontedTransport via CDN={} -> real={}",
            self.config.cdn_host.as_deref().unwrap_or("(none)"),
            self.config.relay_url
        )
    }
}

// ────────────────────────────────────────────────────────────────────────────
// 3. Cloud API Relay Transport
// ────────────────────────────────────────────────────────────────────────────

/// Delivers evidence via cloud storage presigned URLs.
///
/// Evidence is uploaded with an HTTPS PUT to a presigned S3/GCS/Azure URL,
/// which looks like normal cloud storage traffic to network monitors.
///
/// The presigned URL is obtained from the JOCKEY API at agent registration
/// time or via a domain-fronted bootstrap request.
pub struct CloudApiRelayTransport {
    config: TransportConfig,
}

impl CloudApiRelayTransport {
    pub fn new(config: TransportConfig) -> Result<Self, TransportError> {
        if config.upload_presigned_url.is_none() {
            return Err(TransportError::Config(
                "CloudApiRelayTransport requires upload_presigned_url to be set".to_string(),
            ));
        }
        Ok(Self { config })
    }
}

impl EvidenceTransport for CloudApiRelayTransport {
    fn deliver_evidence(
        &self,
        investigation_name: &str,
        evidence_bytes: &[u8],
    ) -> Result<TransportResult, TransportError> {
        let url = self.config.upload_presigned_url.as_deref().ok_or_else(|| {
            TransportError::Config("upload_presigned_url is not set".to_string())
        })?;

        // Add investigation name as a query param to the presigned URL
        let url_with_name = format!("{}&investigation={}", url, investigation_name);

        // Perform an HTTPS PUT (presigned URLs use PUT for S3/GCS)
        put_via_http(
            &url_with_name,
            evidence_bytes,
            self.config.timeout_secs,
            TransportKind::CloudApiRelay,
        )
    }

    fn poll_command(&self) -> Result<Option<String>, TransportError> {
        // Poll SQS/Pub-Sub for pending commands via presigned GET
        if let Some(poll_url) = &self.config.poll_presigned_url {
            let result = http_get(poll_url, self.config.timeout_secs)?;
            if result.is_empty() || result == "null" || result == "{}" {
                Ok(None)
            } else {
                Ok(Some(result))
            }
        } else {
            Ok(None)
        }
    }

    fn describe(&self) -> String {
        format!(
            "CloudApiRelayTransport via {} presigned URL",
            self.config
                .cloud_provider
                .map(|p| format!("{:?}", p))
                .unwrap_or_else(|| "generic".to_string())
        )
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Factory
// ────────────────────────────────────────────────────────────────────────────

/// Build the appropriate transport from a `TransportConfig`.
pub fn build_transport(
    config: TransportConfig,
) -> Result<Box<dyn EvidenceTransport>, TransportError> {
    match config.kind {
        TransportKind::Direct => Ok(Box::new(DirectTransport::new(config))),
        TransportKind::DomainFronted => {
            Ok(Box::new(DomainFrontedTransport::new(config)?))
        }
        TransportKind::CloudApiRelay => {
            Ok(Box::new(CloudApiRelayTransport::new(config)?))
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// HTTP helper functions (no Tokio / async — sync for use in generated binaries)
// ────────────────────────────────────────────────────────────────────────────

/// Perform a synchronous HTTPS POST with optional Host override and
/// X-Jockey-Target header for domain fronting.
fn deliver_via_http(
    url: &str,
    host_override: Option<&str>,
    real_target: Option<&str>,
    body: &[u8],
    timeout_secs: u64,
    kind: TransportKind,
) -> Result<TransportResult, TransportError> {
    // In a real deployment this uses the `ureq` or `minreq` crate for
    // sync HTTP without importing the async Tokio runtime (which has a
    // recognisable syscall pattern). For now we produce a clear stub that
    // documents what would be done:
    let _ = (url, host_override, real_target, timeout_secs);

    // TODO: replace stub with ureq::AgentBuilder::new()
    //   .timeout(Duration::from_secs(timeout_secs))
    //   .build()
    //   .post(url)
    //   .set("Content-Type", "application/json")
    //   .set("Host", host_override.unwrap_or(parsed_host))
    //   .set("X-Jockey-Target", real_target.unwrap_or(""))
    //   .send_bytes(body)

    Ok(TransportResult {
        success: true,
        bytes_transferred: body.len(),
        response_code: Some(200),
        transport_kind: kind,
        note: format!(
            "[stub] Would POST {} bytes to {} via {:?}",
            body.len(),
            url,
            kind
        ),
    })
}

/// Perform a synchronous HTTPS PUT (presigned URL upload).
fn put_via_http(
    url: &str,
    body: &[u8],
    timeout_secs: u64,
    kind: TransportKind,
) -> Result<TransportResult, TransportError> {
    let _ = (url, timeout_secs);
    // TODO: ureq::put(url).set("Content-Type", "application/octet-stream").send_bytes(body)
    Ok(TransportResult {
        success: true,
        bytes_transferred: body.len(),
        response_code: Some(200),
        transport_kind: kind,
        note: format!("[stub] Would PUT {} bytes to presigned URL", body.len()),
    })
}

/// Perform a synchronous HTTPS GET (command poll).
fn http_get(url: &str, timeout_secs: u64) -> Result<String, TransportError> {
    let _ = (url, timeout_secs);
    // TODO: ureq::get(url).call()?.into_string()
    Ok(String::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_kind_from_str() {
        assert_eq!("direct".parse::<TransportKind>().unwrap(), TransportKind::Direct);
        assert_eq!(
            "domain_fronted".parse::<TransportKind>().unwrap(),
            TransportKind::DomainFronted
        );
        assert_eq!(
            "cloud_api_relay".parse::<TransportKind>().unwrap(),
            TransportKind::CloudApiRelay
        );
        assert!("invalid".parse::<TransportKind>().is_err());
    }

    #[test]
    fn test_build_direct_transport() {
        let config = TransportConfig {
            kind: TransportKind::Direct,
            relay_url: "https://jockey.example.com".to_string(),
            ..Default::default()
        };
        let transport = build_transport(config).unwrap();
        assert!(transport.describe().contains("Direct"));
    }

    #[test]
    fn test_build_domain_fronted_transport() {
        let config = TransportConfig {
            kind: TransportKind::DomainFronted,
            relay_url: "https://jockey.example.com".to_string(),
            cdn_host: Some("cloudflare.com".to_string()),
            ..Default::default()
        };
        let transport = build_transport(config).unwrap();
        assert!(transport.describe().contains("DomainFronted"));
        assert!(transport.describe().contains("cloudflare.com"));
    }

    #[test]
    fn test_domain_fronted_requires_cdn_host() {
        let config = TransportConfig {
            kind: TransportKind::DomainFronted,
            relay_url: "https://jockey.example.com".to_string(),
            cdn_host: None, // missing!
            ..Default::default()
        };
        assert!(build_transport(config).is_err());
    }

    #[test]
    fn test_cloud_relay_requires_upload_url() {
        let config = TransportConfig {
            kind: TransportKind::CloudApiRelay,
            upload_presigned_url: None, // missing!
            ..Default::default()
        };
        assert!(build_transport(config).is_err());
    }

    #[test]
    fn test_direct_deliver_evidence_stub() {
        let config = TransportConfig::default();
        let transport = DirectTransport::new(config);
        let result = transport.deliver_evidence("test_investigation", b"{}").unwrap();
        assert!(result.success);
        assert_eq!(result.bytes_transferred, 2);
    }
}
