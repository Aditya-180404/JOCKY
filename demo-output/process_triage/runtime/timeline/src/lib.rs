//! jocky Runtime - Forensic Timeline Engine
//!
//! Normalizes forensic events from multiple sources (processes, network,
//! filesystem, logs, security events) into a unified chronological timeline.
//!
//! Each timeline event has a normalized set of fields regardless of source,
//! making cross-source correlation simple and deterministic.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A normalized forensic timeline event
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TimelineEvent {
    /// UTC timestamp of the event
    pub timestamp: DateTime<Utc>,
    /// Hostname where the event occurred
    pub host: String,
    /// Event source system (e.g. "process", "network", "filesystem", "log", "security")
    pub source: String,
    /// Normalized event type (e.g. "process_created", "connection_established", "file_written")
    pub event_type: String,
    /// Actor responsible (username, PID, or service name)
    pub actor: Option<String>,
    /// Subject acted upon (target path, remote address, etc.)
    pub target: Option<String>,
    /// Associated process name
    pub process_name: Option<String>,
    /// Associated process ID
    pub process_id: Option<i64>,
    /// File or path involved
    pub path: Option<String>,
    /// Network endpoint (address:port) involved
    pub network_endpoint: Option<String>,
    /// Reference to evidence item (for provenance chaining)
    pub evidence_ref: Option<String>,
    /// Additional key-value details from the original record
    pub details: serde_json::Map<String, serde_json::Value>,
}

impl TimelineEvent {
    /// Create a new timeline event with required fields
    pub fn new(
        timestamp: DateTime<Utc>,
        host: impl Into<String>,
        source: impl Into<String>,
        event_type: impl Into<String>,
    ) -> Self {
        Self {
            timestamp,
            host: host.into(),
            source: source.into(),
            event_type: event_type.into(),
            actor: None,
            target: None,
            process_name: None,
            process_id: None,
            path: None,
            network_endpoint: None,
            evidence_ref: None,
            details: serde_json::Map::new(),
        }
    }

    pub fn with_actor(mut self, actor: impl Into<String>) -> Self {
        self.actor = Some(actor.into());
        self
    }

    pub fn with_target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }

    pub fn with_process(mut self, name: impl Into<String>, pid: i64) -> Self {
        self.process_name = Some(name.into());
        self.process_id = Some(pid);
        self
    }

    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    pub fn with_network_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.network_endpoint = Some(endpoint.into());
        self
    }

    pub fn with_evidence_ref(mut self, evidence_ref: impl Into<String>) -> Self {
        self.evidence_ref = Some(evidence_ref.into());
        self
    }

    pub fn with_detail(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.details.insert(key.into(), value);
        self
    }
}

impl PartialOrd for TimelineEvent {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TimelineEvent {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.timestamp.cmp(&other.timestamp)
    }
}

/// A complete forensic timeline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicTimeline {
    pub host: String,
    pub generated_at: DateTime<Utc>,
    pub event_count: usize,
    pub sources: Vec<String>,
    pub events: Vec<TimelineEvent>,
}

impl ForensicTimeline {
    /// Create an empty timeline
    pub fn new(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            generated_at: Utc::now(),
            event_count: 0,
            sources: Vec::new(),
            events: Vec::new(),
        }
    }

    /// Add an event to the timeline
    pub fn add_event(&mut self, event: TimelineEvent) {
        if !self.sources.contains(&event.source) {
            self.sources.push(event.source.clone());
        }
        self.events.push(event);
        self.event_count = self.events.len();
    }

    /// Sort events by timestamp (ascending)
    pub fn sort(&mut self) {
        self.events.sort();
        self.event_count = self.events.len();
    }

    /// Filter events by event type
    pub fn filter_by_type(&self, event_type: &str) -> Vec<&TimelineEvent> {
        self.events
            .iter()
            .filter(|e| e.event_type == event_type)
            .collect()
    }

    /// Filter events by source
    pub fn filter_by_source(&self, source: &str) -> Vec<&TimelineEvent> {
        self.events.iter().filter(|e| e.source == source).collect()
    }

    /// Filter events in a time range
    pub fn filter_by_time_range(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Vec<&TimelineEvent> {
        self.events
            .iter()
            .filter(|e| e.timestamp >= from && e.timestamp <= to)
            .collect()
    }

    /// Get events involving a specific process name
    pub fn filter_by_process(&self, process_name: &str) -> Vec<&TimelineEvent> {
        self.events
            .iter()
            .filter(|e| {
                e.process_name
                    .as_deref()
                    .is_some_and(|n| n.eq_ignore_ascii_case(process_name))
            })
            .collect()
    }

    /// Export to JSON
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Export to CSV
    pub fn to_csv(&self) -> String {
        let mut csv = "timestamp,host,source,event_type,actor,target,process_name,process_id,path,network_endpoint,evidence_ref\n".to_string();
        for event in &self.events {
            csv.push_str(&format!(
                "{},{},{},{},{},{},{},{},{},{},{}\n",
                event.timestamp.to_rfc3339(),
                escape_csv(&event.host),
                escape_csv(&event.source),
                escape_csv(&event.event_type),
                event.actor.as_deref().map(escape_csv).unwrap_or_default(),
                event.target.as_deref().map(escape_csv).unwrap_or_default(),
                event
                    .process_name
                    .as_deref()
                    .map(escape_csv)
                    .unwrap_or_default(),
                event.process_id.map(|p| p.to_string()).unwrap_or_default(),
                event.path.as_deref().map(escape_csv).unwrap_or_default(),
                event
                    .network_endpoint
                    .as_deref()
                    .map(escape_csv)
                    .unwrap_or_default(),
                event
                    .evidence_ref
                    .as_deref()
                    .map(escape_csv)
                    .unwrap_or_default(),
            ));
        }
        csv
    }
}

fn escape_csv(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// Normalize a JSON forensic record into a timeline event, inferring source and type.
pub fn normalize_record(
    record: &serde_json::Value,
    host: &str,
    evidence_ref: Option<&str>,
) -> Option<TimelineEvent> {
    let obj = record.as_object()?;

    // Determine timestamp from various field names
    let timestamp = [
        "timestamp",
        "start_time",
        "created_at",
        "time",
        "event_time",
    ]
    .iter()
    .find_map(|field| {
        obj.get(*field)
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<DateTime<Utc>>().ok())
    })
    .unwrap_or_else(Utc::now);

    // Detect source type from record fields
    let (source, event_type) = detect_source_and_type(obj);

    let mut event = TimelineEvent::new(timestamp, host, &source, &event_type);

    // Set process info
    if let Some(pid) = obj.get("pid").and_then(|v| v.as_i64()) {
        let name = obj
            .get("name")
            .or_else(|| obj.get("process_name"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        event = event.with_process(name, pid);
    }

    // Set path
    if let Some(path) = obj
        .get("path")
        .or_else(|| obj.get("executable"))
        .and_then(|v| v.as_str())
    {
        event = event.with_path(path);
    }

    // Set network endpoint
    if let Some(remote) = obj
        .get("remote_address")
        .or_else(|| obj.get("remote_addr"))
        .and_then(|v| v.as_str())
    {
        let port = obj
            .get("remote_port")
            .and_then(|v| v.as_u64())
            .map(|p| format!(":{}", p))
            .unwrap_or_default();
        event = event.with_network_endpoint(format!("{}{}", remote, port));
    }

    // Set actor (username or user_id)
    if let Some(actor) = obj
        .get("username")
        .or_else(|| obj.get("user"))
        .or_else(|| obj.get("owner"))
        .and_then(|v| v.as_str())
    {
        event = event.with_actor(actor);
    }

    // Set evidence reference
    if let Some(ev_ref) = evidence_ref {
        event = event.with_evidence_ref(ev_ref);
    }

    // Copy remaining fields to details
    for (key, value) in obj {
        if ![
            "timestamp",
            "start_time",
            "created_at",
            "time",
            "event_time",
            "pid",
            "name",
            "process_name",
            "path",
            "executable",
            "remote_address",
            "remote_addr",
            "remote_port",
            "username",
            "user",
            "owner",
        ]
        .contains(&key.as_str())
        {
            event.details.insert(key.clone(), value.clone());
        }
    }

    Some(event)
}

fn detect_source_and_type(obj: &serde_json::Map<String, serde_json::Value>) -> (String, String) {
    // Network events
    if obj.contains_key("remote_address") || obj.contains_key("local_port") {
        let state = obj
            .get("state")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        return (
            "network".to_string(),
            format!("connection_{}", state.to_lowercase()),
        );
    }

    // Process events
    if obj.contains_key("pid") && (obj.contains_key("name") || obj.contains_key("command_line")) {
        return ("process".to_string(), "process_observed".to_string());
    }

    // File events
    if obj.contains_key("path")
        && (obj.contains_key("size") || obj.contains_key("permissions") || obj.contains_key("hash"))
    {
        return ("filesystem".to_string(), "file_observed".to_string());
    }

    // Driver events
    if obj.contains_key("ref_count") || obj.contains_key("vulnerability_indicators") {
        return ("drivers".to_string(), "driver_loaded".to_string());
    }

    // Security finding events
    if obj.contains_key("severity") && obj.contains_key("category") {
        return ("security".to_string(), "security_finding".to_string());
    }

    // Log events
    if obj.contains_key("message") || obj.contains_key("log_level") {
        return ("log".to_string(), "log_entry".to_string());
    }

    // System info
    if obj.contains_key("hostname") || obj.contains_key("os_version") {
        return ("system".to_string(), "system_info_collected".to_string());
    }

    ("unknown".to_string(), "event_recorded".to_string())
}

/// Build a timeline from a collection of forensic evidence records
pub fn build_timeline(
    records: &[serde_json::Value],
    host: &str,
    sources_filter: Option<&[&str]>,
) -> ForensicTimeline {
    let mut timeline = ForensicTimeline::new(host);

    for (index, record) in records.iter().enumerate() {
        if let Some(event) = normalize_record(record, host, Some(&format!("record-{}", index))) {
            if let Some(filter) = sources_filter {
                if !filter.contains(&event.source.as_str()) {
                    continue;
                }
            }
            timeline.add_event(event);
        }
    }

    timeline.sort();
    timeline
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timeline_event_ordering() {
        let t1 = TimelineEvent::new(
            "2024-01-01T10:00:00Z".parse().unwrap(),
            "host1",
            "process",
            "process_created",
        );
        let t2 = TimelineEvent::new(
            "2024-01-01T11:00:00Z".parse().unwrap(),
            "host1",
            "network",
            "connection_established",
        );
        assert!(t1 < t2);
    }

    #[test]
    fn test_build_timeline_from_records() {
        let records = vec![
            serde_json::json!({
                "pid": 1234,
                "name": "powershell.exe",
                "command_line": "powershell -enc ...",
                "start_time": "2024-01-01T10:00:00Z"
            }),
            serde_json::json!({
                "remote_address": "192.168.1.1",
                "remote_port": 4444,
                "state": "ESTABLISHED"
            }),
        ];

        let timeline = build_timeline(&records, "testhost", None);
        assert_eq!(timeline.events.len(), 2);
        assert!(timeline.sources.contains(&"process".to_string()));
        assert!(timeline.sources.contains(&"network".to_string()));
    }

    #[test]
    fn test_normalize_process_record() {
        let record = serde_json::json!({
            "pid": 4567,
            "name": "svchost.exe",
            "path": "C:\\Windows\\System32\\svchost.exe",
            "timestamp": "2024-06-15T08:30:00Z"
        });

        let event = normalize_record(&record, "DESKTOP-ABC123", None).unwrap();
        assert_eq!(event.source, "process");
        assert_eq!(event.process_name.as_deref(), Some("svchost.exe"));
        assert_eq!(event.process_id, Some(4567));
    }

    #[test]
    fn test_timeline_to_csv() {
        let mut timeline = ForensicTimeline::new("testhost");
        let event = TimelineEvent::new(
            "2024-01-01T12:00:00Z".parse().unwrap(),
            "testhost",
            "process",
            "process_observed",
        )
        .with_process("notepad.exe", 9876);
        timeline.add_event(event);

        let csv = timeline.to_csv();
        assert!(csv.contains("notepad.exe"));
        assert!(csv.contains("process_observed"));
    }

    #[test]
    fn test_filter_by_source() {
        let mut timeline = ForensicTimeline::new("testhost");
        timeline.add_event(TimelineEvent::new(
            Utc::now(),
            "testhost",
            "process",
            "proc_created",
        ));
        timeline.add_event(TimelineEvent::new(
            Utc::now(),
            "testhost",
            "network",
            "conn_est",
        ));

        let proc_events = timeline.filter_by_source("process");
        assert_eq!(proc_events.len(), 1);
        let net_events = timeline.filter_by_source("network");
        assert_eq!(net_events.len(), 1);
    }
}
