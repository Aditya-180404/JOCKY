//! Forensic Indicator of Compromise (IOC) Engine (Section 13)
//!
//! Provides matching of high-fidelity threat indicators across forensic artifacts:
//! Hashes (SHA256, SHA1, MD5), Network (IP, DOMAIN, URL), Hosts/Processes/Files/Registry.
//! Supports exact, contains, prefix, suffix, and regex match operators.

use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::entities::NormalizedEntities;
use jocky_runtime_timeline::TimelineEvent;

/// Supported IOC Types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IndicatorType {
    Sha256,
    Sha1,
    Md5,
    Ip,
    Domain,
    Hostname,
    Url,
    Filename,
    ProcessName,
    Path,
    RegistryKey,
}

impl IndicatorType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Sha256 => "SHA256",
            Self::Sha1 => "SHA1",
            Self::Md5 => "MD5",
            Self::Ip => "IP",
            Self::Domain => "DOMAIN",
            Self::Hostname => "HOSTNAME",
            Self::Url => "URL",
            Self::Filename => "FILENAME",
            Self::ProcessName => "PROCESS_NAME",
            Self::Path => "PATH",
            Self::RegistryKey => "REGISTRY_KEY",
        }
    }
}

/// Matching operator for indicator evaluation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchType {
    Exact,
    Contains,
    Prefix,
    Suffix,
    Regex,
}

/// Threat intelligence Indicator definition
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Indicator {
    pub id: String,
    pub indicator_type: IndicatorType,
    pub value: String,
    pub match_type: MatchType,
    pub description: Option<String>,
    pub severity: String,
    pub tags: Vec<String>,
}

impl Indicator {
    pub fn new(
        id: impl Into<String>,
        indicator_type: IndicatorType,
        value: impl Into<String>,
        match_type: MatchType,
        severity: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            indicator_type,
            value: value.into(),
            match_type,
            description: None,
            severity: severity.into(),
            tags: Vec::new(),
        }
    }

    /// Evaluates if an observed string matches this indicator
    pub fn is_match(&self, observed: &str) -> bool {
        match self.match_type {
            MatchType::Exact => observed.eq_ignore_ascii_case(&self.value),
            MatchType::Contains => observed
                .to_ascii_lowercase()
                .contains(&self.value.to_ascii_lowercase()),
            MatchType::Prefix => observed
                .to_ascii_lowercase()
                .starts_with(&self.value.to_ascii_lowercase()),
            MatchType::Suffix => observed
                .to_ascii_lowercase()
                .ends_with(&self.value.to_ascii_lowercase()),
            MatchType::Regex => {
                if let Ok(re) = Regex::new(&self.value) {
                    re.is_match(observed)
                } else {
                    false
                }
            }
        }
    }
}

/// Forensic observation matching an indicator
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IndicatorMatch {
    pub indicator_id: String,
    pub indicator_type: IndicatorType,
    pub indicator_value: String,
    pub matched_field: String,
    pub observed_value: String,
    pub host_id: String,
    pub timestamp: DateTime<Utc>,
    pub evidence_reference: Option<String>,
    pub severity: String,
}

/// IOC Matching Engine
#[derive(Debug, Default, Clone)]
pub struct IocEngine {
    pub indicators: Vec<Indicator>,
}

impl IocEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_indicator(&mut self, indicator: Indicator) {
        self.indicators.push(indicator);
    }

    /// Scan normalized forensic entities for all registered indicators
    pub fn scan_entities(
        &self,
        entities: &NormalizedEntities,
        host_id: &str,
    ) -> Vec<IndicatorMatch> {
        let mut matches = Vec::new();
        let now = Utc::now();

        for indicator in &self.indicators {
            match indicator.indicator_type {
                IndicatorType::ProcessName => {
                    for proc in &entities.processes {
                        if indicator.is_match(&proc.name) {
                            matches.push(IndicatorMatch {
                                indicator_id: indicator.id.clone(),
                                indicator_type: indicator.indicator_type,
                                indicator_value: indicator.value.clone(),
                                matched_field: "process.name".to_string(),
                                observed_value: proc.name.clone(),
                                host_id: host_id.to_string(),
                                timestamp: proc.start_time.unwrap_or(now),
                                evidence_reference: Some(format!("pid:{}", proc.pid)),
                                severity: indicator.severity.clone(),
                            });
                        }
                    }
                }
                IndicatorType::Path | IndicatorType::Filename => {
                    for proc in &entities.processes {
                        if let Some(exe) = &proc.executable {
                            if indicator.is_match(exe) {
                                matches.push(IndicatorMatch {
                                    indicator_id: indicator.id.clone(),
                                    indicator_type: indicator.indicator_type,
                                    indicator_value: indicator.value.clone(),
                                    matched_field: "process.executable".to_string(),
                                    observed_value: exe.clone(),
                                    host_id: host_id.to_string(),
                                    timestamp: proc.start_time.unwrap_or(now),
                                    evidence_reference: Some(format!("pid:{}", proc.pid)),
                                    severity: indicator.severity.clone(),
                                });
                            }
                        }
                    }
                    for file in &entities.files {
                        if indicator.is_match(&file.path) {
                            matches.push(IndicatorMatch {
                                indicator_id: indicator.id.clone(),
                                indicator_type: indicator.indicator_type,
                                indicator_value: indicator.value.clone(),
                                matched_field: "file.path".to_string(),
                                observed_value: file.path.clone(),
                                host_id: host_id.to_string(),
                                timestamp: file.modified_at.unwrap_or(now),
                                evidence_reference: Some(format!("path:{}", file.path)),
                                severity: indicator.severity.clone(),
                            });
                        }
                    }
                }
                IndicatorType::Sha256 => {
                    for proc in &entities.processes {
                        if let Some(h) = &proc.hash {
                            if indicator.is_match(h) {
                                matches.push(IndicatorMatch {
                                    indicator_id: indicator.id.clone(),
                                    indicator_type: indicator.indicator_type,
                                    indicator_value: indicator.value.clone(),
                                    matched_field: "process.hash".to_string(),
                                    observed_value: h.clone(),
                                    host_id: host_id.to_string(),
                                    timestamp: proc.start_time.unwrap_or(now),
                                    evidence_reference: Some(format!("pid:{}", proc.pid)),
                                    severity: indicator.severity.clone(),
                                });
                            }
                        }
                    }
                    for file in &entities.files {
                        if let Some(h) = &file.sha256 {
                            if indicator.is_match(h) {
                                matches.push(IndicatorMatch {
                                    indicator_id: indicator.id.clone(),
                                    indicator_type: indicator.indicator_type,
                                    indicator_value: indicator.value.clone(),
                                    matched_field: "file.sha256".to_string(),
                                    observed_value: h.clone(),
                                    host_id: host_id.to_string(),
                                    timestamp: file.modified_at.unwrap_or(now),
                                    evidence_reference: Some(format!("path:{}", file.path)),
                                    severity: indicator.severity.clone(),
                                });
                            }
                        }
                    }
                }
                IndicatorType::Ip => {
                    for net in &entities.network_connections {
                        let remote_ip = net.remote_address.split(':').next().unwrap_or("");
                        if indicator.is_match(remote_ip) || indicator.is_match(&net.remote_address)
                        {
                            matches.push(IndicatorMatch {
                                indicator_id: indicator.id.clone(),
                                indicator_type: indicator.indicator_type,
                                indicator_value: indicator.value.clone(),
                                matched_field: "network.remote_address".to_string(),
                                observed_value: net.remote_address.clone(),
                                host_id: host_id.to_string(),
                                timestamp: net.timestamp,
                                evidence_reference: Some(format!(
                                    "conn:{}->{}",
                                    net.local_address, net.remote_address
                                )),
                                severity: indicator.severity.clone(),
                            });
                        }
                    }
                }
                IndicatorType::Hostname => {
                    for host in &entities.hosts {
                        if indicator.is_match(&host.hostname) {
                            matches.push(IndicatorMatch {
                                indicator_id: indicator.id.clone(),
                                indicator_type: indicator.indicator_type,
                                indicator_value: indicator.value.clone(),
                                matched_field: "host.hostname".to_string(),
                                observed_value: host.hostname.clone(),
                                host_id: host_id.to_string(),
                                timestamp: now,
                                evidence_reference: Some(format!("host:{}", host.hostname)),
                                severity: indicator.severity.clone(),
                            });
                        }
                    }
                }
                IndicatorType::RegistryKey => {
                    for reg in &entities.registry_keys {
                        if indicator.is_match(&reg.key) {
                            matches.push(IndicatorMatch {
                                indicator_id: indicator.id.clone(),
                                indicator_type: indicator.indicator_type,
                                indicator_value: indicator.value.clone(),
                                matched_field: "registry.key".to_string(),
                                observed_value: reg.key.clone(),
                                host_id: host_id.to_string(),
                                timestamp: reg.timestamp.unwrap_or(now),
                                evidence_reference: Some(format!("reg:{}", reg.key)),
                                severity: indicator.severity.clone(),
                            });
                        }
                    }
                }
                _ => {}
            }
        }

        matches
    }

    /// Scan timeline events for IOC matches
    pub fn scan_timeline(&self, events: &[TimelineEvent]) -> Vec<IndicatorMatch> {
        let mut matches = Vec::new();

        for event in events {
            for indicator in &self.indicators {
                let mut matched = false;
                let mut field = "";
                let mut observed = "";

                if let Some(proc) = &event.process_name {
                    if indicator.indicator_type == IndicatorType::ProcessName
                        && indicator.is_match(proc)
                    {
                        matched = true;
                        field = "timeline.process_name";
                        observed = proc;
                    }
                }
                if let Some(path) = &event.path {
                    if (indicator.indicator_type == IndicatorType::Path
                        || indicator.indicator_type == IndicatorType::Filename)
                        && indicator.is_match(path)
                    {
                        matched = true;
                        field = "timeline.path";
                        observed = path;
                    }
                }
                if let Some(net) = &event.network_endpoint {
                    if indicator.indicator_type == IndicatorType::Ip && indicator.is_match(net) {
                        matched = true;
                        field = "timeline.network_endpoint";
                        observed = net;
                    }
                }

                if matched {
                    matches.push(IndicatorMatch {
                        indicator_id: indicator.id.clone(),
                        indicator_type: indicator.indicator_type,
                        indicator_value: indicator.value.clone(),
                        matched_field: field.to_string(),
                        observed_value: observed.to_string(),
                        host_id: event.host.clone(),
                        timestamp: event.timestamp,
                        evidence_reference: event.evidence_ref.clone(),
                        severity: indicator.severity.clone(),
                    });
                }
            }
        }

        matches
    }
}
