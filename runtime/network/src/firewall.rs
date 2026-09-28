//! Real Firewall collector and normalizer for JOCKEY
//!
//! Complies with JOCKEY forensic requirements:
//! - Real collector (no mocks, no hardcoded records).
//! - Clean reporting on unsupported platforms or missing backends.
//! - Normalized evidence model matching the JOCKEY forensic schema.
//! - Clear elevation handling (`status: "requires_elevation"` on permission denial).

use serde::{Deserialize, Serialize};

/// Normalized firewall evidence record
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NormalizedFirewallRecord {
    pub collector: String,
    pub artifact_type: String,
    pub status: String, // "present", "requires_elevation", "not_available", "unsupported"
    pub backend: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub firewall_profile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub firewall_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inbound_default_policy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outbound_default_policy: Option<String>,
    pub active_profiles: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_port: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_port: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_association: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_group: Option<String>,
    pub source_metadata: String,
    pub collection_timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Default for NormalizedFirewallRecord {
    fn default() -> Self {
        Self {
            collector: "firewall".to_string(),
            artifact_type: "firewall_rule".to_string(),
            status: "present".to_string(),
            backend: "unknown".to_string(),
            firewall_profile: None,
            firewall_enabled: None,
            inbound_default_policy: None,
            outbound_default_policy: None,
            active_profiles: Vec::new(),
            rule_name: None,
            rule_id: None,
            direction: None,
            action: None,
            enabled: None,
            protocol: None,
            local_address: None,
            remote_address: None,
            local_port: None,
            remote_port: None,
            application_path: None,
            service: None,
            profile_association: None,
            rule_group: None,
            source_metadata: String::new(),
            collection_timestamp: chrono::Utc::now().to_rfc3339(),
            error: None,
        }
    }
}

impl NormalizedFirewallRecord {
    pub fn requires_elevation(backend: impl Into<String>, error: impl Into<String>) -> Self {
        Self {
            collector: "firewall".to_string(),
            artifact_type: "firewall_status".to_string(),
            status: "requires_elevation".to_string(),
            backend: backend.into(),
            error: Some(error.into()),
            collection_timestamp: chrono::Utc::now().to_rfc3339(),
            ..Default::default()
        }
    }

    pub fn not_available(backend: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            collector: "firewall".to_string(),
            artifact_type: "firewall_status".to_string(),
            status: "not_available".to_string(),
            backend: backend.into(),
            error: Some(reason.into()),
            collection_timestamp: chrono::Utc::now().to_rfc3339(),
            ..Default::default()
        }
    }

    pub fn unsupported(platform: &str) -> Self {
        Self {
            collector: "firewall".to_string(),
            artifact_type: "firewall_status".to_string(),
            status: "unsupported".to_string(),
            backend: "none".to_string(),
            error: Some(format!(
                "Firewall collection is not supported on platform '{}'",
                platform
            )),
            collection_timestamp: chrono::Utc::now().to_rfc3339(),
            ..Default::default()
        }
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_else(|_| {
            serde_json::json!({
                "collector": "firewall",
                "artifact_type": self.artifact_type,
                "status": self.status,
                "backend": self.backend,
            })
        })
    }
}

/// Normalize direction strings
pub fn normalize_direction(raw: &str) -> String {
    let lower = raw.to_lowercase();
    if lower.contains("in") || lower == "1" {
        "inbound".to_string()
    } else if lower.contains("out") || lower == "2" {
        "outbound".to_string()
    } else {
        raw.to_string()
    }
}

/// Normalize action strings
pub fn normalize_action(raw: &str) -> String {
    let lower = raw.to_lowercase();
    if lower.contains("allow") || lower == "2" || lower == "accept" {
        "allow".to_string()
    } else if lower.contains("block") || lower == "4" || lower == "drop" || lower == "reject" {
        "block".to_string()
    } else {
        raw.to_string()
    }
}

/// Normalize protocol strings
pub fn normalize_protocol(raw: &str) -> String {
    let lower = raw.trim().to_lowercase();
    match lower.as_str() {
        "6" | "tcp" => "tcp".to_string(),
        "17" | "udp" => "udp".to_string(),
        "1" | "icmp" => "icmp".to_string(),
        "58" | "icmpv6" => "icmpv6".to_string(),
        "256" | "any" | "*" => "any".to_string(),
        _ => lower,
    }
}

/// Parse Windows PowerShell Get-NetFirewallProfile JSON array/object
pub fn parse_windows_profiles(
    val: &serde_json::Value,
) -> (Vec<String>, Vec<NormalizedFirewallRecord>) {
    let items = match val {
        serde_json::Value::Array(arr) => arr.clone(),
        serde_json::Value::Object(_) => vec![val.clone()],
        _ => vec![],
    };

    let mut active_profiles = Vec::new();
    let mut records = Vec::new();

    for item in items {
        let name = item
            .get("Name")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown")
            .to_string();
        let enabled_val = item.get("Enabled").and_then(|v| v.as_i64()).unwrap_or(0);
        let enabled = enabled_val == 1;

        if enabled {
            active_profiles.push(name.clone());
        }

        let inbound_action = match item
            .get("DefaultInboundAction")
            .and_then(|v| v.as_i64())
            .unwrap_or(0)
        {
            1 => "block",
            2 => "allow",
            _ => "block", // default Windows inbound policy is block
        };

        let outbound_action = match item
            .get("DefaultOutboundAction")
            .and_then(|v| v.as_i64())
            .unwrap_or(0)
        {
            1 => "block",
            2 => "allow",
            _ => "allow", // default Windows outbound policy is allow
        };

        records.push(NormalizedFirewallRecord {
            collector: "firewall".to_string(),
            artifact_type: "firewall_profile".to_string(),
            status: "present".to_string(),
            backend: "windows_netfirewall".to_string(),
            firewall_profile: Some(name),
            firewall_enabled: Some(enabled),
            inbound_default_policy: Some(inbound_action.to_string()),
            outbound_default_policy: Some(outbound_action.to_string()),
            active_profiles: vec![],
            source_metadata: "Get-NetFirewallProfile".to_string(),
            collection_timestamp: chrono::Utc::now().to_rfc3339(),
            ..Default::default()
        });
    }

    (active_profiles, records)
}

/// Parse Windows PowerShell Get-NetFirewallRule JSON array/object
pub fn parse_windows_rules(
    val: &serde_json::Value,
    active_profiles: &[String],
) -> Vec<NormalizedFirewallRecord> {
    let items = match val {
        serde_json::Value::Array(arr) => arr.clone(),
        serde_json::Value::Object(_) => vec![val.clone()],
        _ => vec![],
    };

    let mut records = Vec::new();

    for item in items {
        let name = item
            .get("Name")
            .and_then(|v| v.as_str())
            .map(ToString::to_string);
        let display_name = item
            .get("DisplayName")
            .and_then(|v| v.as_str())
            .map(ToString::to_string);
        let rule_id = name.clone();
        let rule_name = display_name.or(name);

        let enabled_val = item
            .get("Enabled")
            .and_then(|v| {
                if let Some(i) = v.as_i64() {
                    Some(i == 1)
                } else if let Some(b) = v.as_bool() {
                    Some(b)
                } else {
                    v.as_str()
                        .map(|s| s.eq_ignore_ascii_case("true") || s == "1")
                }
            })
            .unwrap_or(true);

        let direction_str = item
            .get("Direction")
            .map(|v| v.to_string())
            .unwrap_or_default();
        let direction = Some(normalize_direction(&direction_str));

        let action_str = item
            .get("Action")
            .map(|v| v.to_string())
            .unwrap_or_default();
        let action = Some(normalize_action(&action_str));

        let protocol = item
            .get("Protocol")
            .and_then(|v| v.as_str())
            .map(normalize_protocol);
        let local_port = item
            .get("LocalPort")
            .and_then(|v| v.as_str())
            .map(ToString::to_string);
        let remote_port = item
            .get("RemotePort")
            .and_then(|v| v.as_str())
            .map(ToString::to_string);
        let program = item
            .get("Program")
            .and_then(|v| v.as_str())
            .map(ToString::to_string);
        let service = item
            .get("Service")
            .and_then(|v| v.as_str())
            .map(ToString::to_string);
        let group = item
            .get("DisplayGroup")
            .or_else(|| item.get("RuleGroup"))
            .and_then(|v| v.as_str())
            .map(ToString::to_string);
        let profiles = item
            .get("Profile")
            .or_else(|| item.get("Profiles"))
            .map(|v| v.to_string());

        records.push(NormalizedFirewallRecord {
            collector: "firewall".to_string(),
            artifact_type: "firewall_rule".to_string(),
            status: "present".to_string(),
            backend: "windows_netfirewall".to_string(),
            active_profiles: active_profiles.to_vec(),
            rule_name,
            rule_id,
            direction,
            action,
            enabled: Some(enabled_val),
            protocol,
            local_address: item
                .get("LocalAddress")
                .and_then(|v| v.as_str())
                .map(ToString::to_string),
            remote_address: item
                .get("RemoteAddress")
                .and_then(|v| v.as_str())
                .map(ToString::to_string),
            local_port,
            remote_port,
            application_path: program,
            service,
            profile_association: profiles,
            rule_group: group,
            source_metadata: "Get-NetFirewallRule".to_string(),
            collection_timestamp: chrono::Utc::now().to_rfc3339(),
            ..Default::default()
        });
    }

    records
}

/// Parse Linux iptables-save / iptables -S output into normalized firewall records
pub fn parse_iptables_output(output: &str) -> Vec<NormalizedFirewallRecord> {
    let mut records = Vec::new();

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Policy line: -P INPUT DROP (from iptables -S) or :INPUT DROP [0:0] (from iptables-save)
        let policy_entry = if let Some(rest) = line.strip_prefix("-P ") {
            let mut parts = rest.split_whitespace();
            parts.next().zip(parts.next())
        } else if let Some(rest) = line.strip_prefix(':') {
            let mut parts = rest.split_whitespace();
            parts.next().zip(parts.next())
        } else {
            None
        };

        if let Some((chain, target)) = policy_entry {
            records.push(NormalizedFirewallRecord {
                collector: "firewall".to_string(),
                artifact_type: "firewall_profile".to_string(),
                status: "present".to_string(),
                backend: "iptables".to_string(),
                firewall_profile: Some(chain.to_string()),
                firewall_enabled: Some(true),
                inbound_default_policy: if chain == "INPUT" {
                    Some(normalize_action(target))
                } else {
                    None
                },
                outbound_default_policy: if chain == "OUTPUT" {
                    Some(normalize_action(target))
                } else {
                    None
                },
                active_profiles: vec![chain.to_string()],
                source_metadata: line.to_string(),
                collection_timestamp: chrono::Utc::now().to_rfc3339(),
                ..Default::default()
            });
            continue;
        }

        // Rule line: -A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
        if let Some(rest) = line.strip_prefix("-A ") {
            let tokens: Vec<&str> = rest.split_whitespace().collect();
            if tokens.is_empty() {
                continue;
            }

            let chain = tokens[0];
            let direction = match chain {
                "INPUT" | "PREROUTING" => "inbound",
                "OUTPUT" | "POSTROUTING" => "outbound",
                "FORWARD" => "forward",
                _ => chain,
            };

            let mut protocol = None;
            let mut local_port = None;
            let mut remote_port = None;
            let mut local_address = None;
            let mut remote_address = None;
            let mut action = None;

            let mut idx = 1;
            while idx < tokens.len() {
                match tokens[idx] {
                    "-p" if idx + 1 < tokens.len() => {
                        protocol = Some(normalize_protocol(tokens[idx + 1]));
                        idx += 2;
                    }
                    "-s" if idx + 1 < tokens.len() => {
                        remote_address = Some(tokens[idx + 1].to_string());
                        idx += 2;
                    }
                    "-d" if idx + 1 < tokens.len() => {
                        local_address = Some(tokens[idx + 1].to_string());
                        idx += 2;
                    }
                    "--dport" if idx + 1 < tokens.len() => {
                        local_port = Some(tokens[idx + 1].to_string());
                        idx += 2;
                    }
                    "--sport" if idx + 1 < tokens.len() => {
                        remote_port = Some(tokens[idx + 1].to_string());
                        idx += 2;
                    }
                    "-j" if idx + 1 < tokens.len() => {
                        action = Some(normalize_action(tokens[idx + 1]));
                        idx += 2;
                    }
                    _ => idx += 1,
                }
            }

            records.push(NormalizedFirewallRecord {
                collector: "firewall".to_string(),
                artifact_type: "firewall_rule".to_string(),
                status: "present".to_string(),
                backend: "iptables".to_string(),
                rule_name: Some(format!("iptables-{}-rule-{}", chain, records.len() + 1)),
                rule_id: Some(format!("iptables-{}-{}", chain, records.len() + 1)),
                direction: Some(direction.to_string()),
                action,
                enabled: Some(true),
                protocol,
                local_address,
                remote_address,
                local_port,
                remote_port,
                source_metadata: line.to_string(),
                collection_timestamp: chrono::Utc::now().to_rfc3339(),
                ..Default::default()
            });
        }
    }

    records
}

/// Collect Windows firewall rules & profiles
#[cfg(target_os = "windows")]
pub fn collect_windows_firewall(
) -> Result<Vec<NormalizedFirewallRecord>, Box<dyn std::error::Error>> {
    let mut all_records = Vec::new();

    // 1. Collect profiles
    let profile_cmd = "Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction | ConvertTo-Json -Compress";
    let profile_out = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", profile_cmd])
        .output();

    let mut active_profiles = Vec::new();
    match profile_out {
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            if !out.status.success()
                && (stderr.contains("PermissionDenied") || stderr.contains("UnauthorizedAccess"))
            {
                return Ok(vec![NormalizedFirewallRecord::requires_elevation(
                    "windows_netfirewall",
                    "Querying Windows Firewall profiles requires administrator privileges",
                )]);
            }
            let stdout = String::from_utf8_lossy(&out.stdout);
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&stdout) {
                let (act, mut prof_records) = parse_windows_profiles(&val);
                active_profiles = act;
                all_records.append(&mut prof_records);
            }
        }
        Err(e) => {
            return Ok(vec![NormalizedFirewallRecord::not_available(
                "windows_netfirewall",
                format!("Failed to execute PowerShell: {}", e),
            )]);
        }
    }

    // 2. Collect rules
    let rule_cmd = "Get-NetFirewallRule | Select-Object -First 250 Name,DisplayName,Enabled,Direction,Action,Profile,DisplayGroup | ConvertTo-Json -Compress";
    let rule_out = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", rule_cmd])
        .output();

    match rule_out {
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            if !out.status.success()
                && (stderr.contains("PermissionDenied") || stderr.contains("UnauthorizedAccess"))
            {
                if all_records.is_empty() {
                    return Ok(vec![NormalizedFirewallRecord::requires_elevation(
                        "windows_netfirewall",
                        "Querying Windows Firewall rules requires administrator privileges",
                    )]);
                }
            } else {
                let stdout = String::from_utf8_lossy(&out.stdout);
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&stdout) {
                    let mut rule_records = parse_windows_rules(&val, &active_profiles);
                    all_records.append(&mut rule_records);
                }
            }
        }
        Err(e) => {
            if all_records.is_empty() {
                return Ok(vec![NormalizedFirewallRecord::not_available(
                    "windows_netfirewall",
                    format!("Failed to execute PowerShell for firewall rules: {}", e),
                )]);
            }
        }
    }

    if all_records.is_empty() {
        all_records.push(NormalizedFirewallRecord::not_available(
            "windows_netfirewall",
            "No firewall rules or profiles returned by Windows host",
        ));
    }

    Ok(all_records)
}

/// Collect Linux firewall rules & profiles safely (nftables, iptables, firewalld, ufw)
#[cfg(target_os = "linux")]
pub fn collect_linux_firewall() -> Result<Vec<NormalizedFirewallRecord>, Box<dyn std::error::Error>>
{
    // 1. Try nftables
    if let Ok(out) = std::process::Command::new("nft")
        .args(["list", "ruleset"])
        .output()
    {
        let stderr = String::from_utf8_lossy(&out.stderr);
        if !out.status.success()
            && (stderr.contains("Operation not permitted") || stderr.contains("Permission denied"))
        {
            return Ok(vec![NormalizedFirewallRecord::requires_elevation(
                "nftables",
                "Querying nftables ruleset requires root privileges (CAP_NET_ADMIN)",
            )]);
        }
        if out.status.success() {
            let stdout = String::from_utf8_lossy(&out.stdout);
            if !stdout.trim().is_empty() {
                let mut records = Vec::new();
                for (idx, line) in stdout.lines().enumerate() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() || trimmed.starts_with('#') {
                        continue;
                    }
                    records.push(NormalizedFirewallRecord {
                        collector: "firewall".to_string(),
                        artifact_type: "firewall_rule".to_string(),
                        status: "present".to_string(),
                        backend: "nftables".to_string(),
                        rule_name: Some(format!("nft-rule-{}", idx + 1)),
                        rule_id: Some(format!("nft-{}", idx + 1)),
                        source_metadata: trimmed.to_string(),
                        collection_timestamp: chrono::Utc::now().to_rfc3339(),
                        ..Default::default()
                    });
                }
                if !records.is_empty() {
                    return Ok(records);
                }
            }
        }
    }

    // 2. Try iptables-save or iptables -S
    for cmd in ["iptables-save", "iptables"] {
        let args: &[&str] = if cmd == "iptables" { &["-S"] } else { &[] };
        if let Ok(out) = std::process::Command::new(cmd).args(args).output() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            if !out.status.success()
                && (stderr.contains("Permission denied") || stderr.contains("must be root"))
            {
                return Ok(vec![NormalizedFirewallRecord::requires_elevation(
                    "iptables",
                    "Querying iptables rules requires root privileges",
                )]);
            }
            if out.status.success() {
                let stdout = String::from_utf8_lossy(&out.stdout);
                let records = parse_iptables_output(&stdout);
                if !records.is_empty() {
                    return Ok(records);
                }
            }
        }
    }

    // 3. Try ufw
    if let Ok(out) = std::process::Command::new("ufw")
        .args(["status", "verbose"])
        .output()
    {
        let stderr = String::from_utf8_lossy(&out.stderr);
        if !out.status.success()
            && (stderr.contains("root") || stderr.contains("Permission denied"))
        {
            return Ok(vec![NormalizedFirewallRecord::requires_elevation(
                "ufw",
                "Querying ufw status requires root privileges",
            )]);
        }
        if out.status.success() {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let mut records = Vec::new();
            for (idx, line) in stdout.lines().enumerate() {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                records.push(NormalizedFirewallRecord {
                    collector: "firewall".to_string(),
                    artifact_type: "firewall_rule".to_string(),
                    status: "present".to_string(),
                    backend: "ufw".to_string(),
                    rule_name: Some(format!("ufw-line-{}", idx + 1)),
                    source_metadata: trimmed.to_string(),
                    collection_timestamp: chrono::Utc::now().to_rfc3339(),
                    ..Default::default()
                });
            }
            if !records.is_empty() {
                return Ok(records);
            }
        }
    }

    // No recognized backend available
    Ok(vec![NormalizedFirewallRecord::not_available(
        "none",
        "No supported firewall system active or available (nftables, iptables, ufw)",
    )])
}

/// Fallback for other platforms
#[cfg(not(any(target_os = "windows", target_os = "linux")))]
pub fn collect_other_firewall() -> Result<Vec<NormalizedFirewallRecord>, Box<dyn std::error::Error>>
{
    Ok(vec![NormalizedFirewallRecord::unsupported(
        std::env::consts::OS,
    )])
}

/// Master function to collect firewall policy and rules
pub fn collect_firewall_policy() -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    #[cfg(target_os = "windows")]
    let records = collect_windows_firewall()?;

    #[cfg(target_os = "linux")]
    let records = collect_linux_firewall()?;

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    let records = collect_other_firewall()?;

    Ok(records.into_iter().map(|r| r.to_json()).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_direction_and_action() {
        assert_eq!(normalize_direction("Inbound"), "inbound");
        assert_eq!(normalize_direction("1"), "inbound");
        assert_eq!(normalize_direction("Outbound"), "outbound");
        assert_eq!(normalize_direction("2"), "outbound");

        assert_eq!(normalize_action("Allow"), "allow");
        assert_eq!(normalize_action("ACCEPT"), "allow");
        assert_eq!(normalize_action("2"), "allow");
        assert_eq!(normalize_action("Block"), "block");
        assert_eq!(normalize_action("DROP"), "block");
        assert_eq!(normalize_action("REJECT"), "block");
        assert_eq!(normalize_action("4"), "block");
    }

    #[test]
    fn test_normalize_protocol() {
        assert_eq!(normalize_protocol("6"), "tcp");
        assert_eq!(normalize_protocol("TCP"), "tcp");
        assert_eq!(normalize_protocol("17"), "udp");
        assert_eq!(normalize_protocol("UDP"), "udp");
        assert_eq!(normalize_protocol("1"), "icmp");
        assert_eq!(normalize_protocol("Any"), "any");
    }

    #[test]
    fn test_parse_windows_profiles_json() {
        let sample = serde_json::json!([
            {
                "Name": "Domain",
                "Enabled": 1,
                "DefaultInboundAction": 1,
                "DefaultOutboundAction": 2
            },
            {
                "Name": "Public",
                "Enabled": 0,
                "DefaultInboundAction": 1,
                "DefaultOutboundAction": 2
            }
        ]);

        let (active, records) = parse_windows_profiles(&sample);
        assert_eq!(active, vec!["Domain"]);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].firewall_profile, Some("Domain".to_string()));
        assert_eq!(records[0].firewall_enabled, Some(true));
        assert_eq!(records[0].inbound_default_policy, Some("block".to_string()));
        assert_eq!(
            records[0].outbound_default_policy,
            Some("allow".to_string())
        );
        assert_eq!(records[1].firewall_enabled, Some(false));
    }

    #[test]
    fn test_parse_windows_rules_json() {
        let sample = serde_json::json!([
            {
                "Name": "SSH-In-TCP",
                "DisplayName": "OpenSSH Server (sshd)",
                "Enabled": 1,
                "Direction": 1,
                "Action": 2,
                "Protocol": "TCP",
                "LocalPort": "22",
                "DisplayGroup": "OpenSSH"
            }
        ]);

        let records = parse_windows_rules(&sample, &["Domain".to_string()]);
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].rule_name,
            Some("OpenSSH Server (sshd)".to_string())
        );
        assert_eq!(records[0].direction, Some("inbound".to_string()));
        assert_eq!(records[0].action, Some("allow".to_string()));
        assert_eq!(records[0].enabled, Some(true));
        assert_eq!(records[0].protocol, Some("tcp".to_string()));
        assert_eq!(records[0].local_port, Some("22".to_string()));
    }

    #[test]
    fn test_parse_iptables_output() {
        let sample = r#"
# Generated by iptables-save
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
-A OUTPUT -p udp --dport 53 -j ACCEPT
COMMIT
"#;
        let records = parse_iptables_output(sample);
        assert_eq!(records.len(), 6); // 3 policies + 3 rules

        let ssh_rule = records
            .iter()
            .find(|r| r.local_port == Some("22".to_string()))
            .unwrap();
        assert_eq!(ssh_rule.direction, Some("inbound".to_string()));
        assert_eq!(ssh_rule.action, Some("allow".to_string()));
        assert_eq!(ssh_rule.protocol, Some("tcp".to_string()));
    }

    #[test]
    fn test_requires_elevation_record() {
        let rec = NormalizedFirewallRecord::requires_elevation("nftables", "Permission denied");
        assert_eq!(rec.status, "requires_elevation");
        assert_eq!(rec.backend, "nftables");
        assert!(rec.error.is_some());
    }

    #[test]
    fn test_not_available_record() {
        let rec = NormalizedFirewallRecord::not_available("none", "No firewall installed");
        assert_eq!(rec.status, "not_available");
        assert_eq!(rec.backend, "none");
    }

    #[test]
    fn test_collect_firewall_policy_runs_without_panics() {
        let res = collect_firewall_policy();
        assert!(res.is_ok());
        let records = res.unwrap();
        assert!(
            !records.is_empty(),
            "Must return at least one firewall record"
        );
        assert_eq!(records[0]["collector"], "firewall");
    }
}
