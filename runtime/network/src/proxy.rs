//! Proxy configuration collector and normalizer for JOCKEY
//!
//! Complies with JOCKEY forensic & security requirements:
//! - NEVER collects, logs, or exports proxy passwords, tokens, cookies, or secrets.
//! - Strips credentials from proxy URLs and reports `authentication_configured: true`.
//! - Normalizes Windows (WinHTTP, WinINET/registry, environment) and Linux (environment,
//!   desktop/system configs) into a single unified schema.

use serde::{Deserialize, Serialize};

/// Normalized proxy configuration record
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NormalizedProxyRecord {
    pub collector: String,
    pub artifact_type: String,
    pub proxy_type: String,
    pub scheme: Option<String>,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub enabled: bool,
    pub source: String,
    pub bypass_list: Vec<String>,
    pub authentication_configured: bool,
    pub timestamp: String,
}

impl NormalizedProxyRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        proxy_type: impl Into<String>,
        scheme: Option<String>,
        host: Option<String>,
        port: Option<u16>,
        enabled: bool,
        source: impl Into<String>,
        bypass_list: Vec<String>,
        authentication_configured: bool,
    ) -> Self {
        Self {
            collector: "proxy".to_string(),
            artifact_type: "proxy_configuration".to_string(),
            proxy_type: proxy_type.into(),
            scheme,
            host,
            port,
            enabled,
            source: source.into(),
            bypass_list,
            authentication_configured,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_else(|_| {
            serde_json::json!({
                "collector": "proxy",
                "artifact_type": "proxy_configuration",
                "proxy_type": self.proxy_type,
                "scheme": self.scheme,
                "host": self.host,
                "port": self.port,
                "enabled": self.enabled,
                "source": self.source,
                "bypass_list": self.bypass_list,
                "authentication_configured": self.authentication_configured,
                "timestamp": self.timestamp,
            })
        })
    }
}

/// Parse a raw proxy endpoint string safely with strict credential redaction.
///
/// Supported formats:
/// - `http://user:password@proxy.example.com:8080` -> host: proxy.example.com, port: 8080, auth: true
/// - `https://user:password@[2001:db8::1]:8443` -> host: 2001:db8::1, port: 8443, auth: true
/// - `socks5://127.0.0.1:1080` -> type: socks5, host: 127.0.0.1, port: 1080, auth: false
/// - `proxy.example.com:3128` -> host: proxy.example.com, port: 3128
/// - `[::1]:8080` -> host: ::1, port: 8080
pub type ProxyEndpointTuple = (String, Option<String>, Option<String>, Option<u16>, bool);

pub fn parse_proxy_endpoint(raw: &str, default_type: &str) -> Option<ProxyEndpointTuple> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Determine scheme and rest of URL
    let (scheme, rest) = if let Some(idx) = trimmed.find("://") {
        let s = &trimmed[..idx];
        let r = &trimmed[idx + 3..];
        (Some(s.to_lowercase()), r)
    } else {
        (None, trimmed)
    };

    // Determine proxy type from scheme or default
    let proxy_type = match scheme.as_deref() {
        Some("socks5") | Some("socks5h") => "socks5".to_string(),
        Some("socks4") | Some("socks4a") => "socks4".to_string(),
        Some("https") => "https".to_string(),
        Some("http") => "http".to_string(),
        _ => default_type.to_string(),
    };

    // Check for path or query and strip them
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);

    // Extract userinfo (credentials) if present
    let (has_auth, host_port) = if let Some(at_idx) = authority.rfind('@') {
        let _credentials_redacted = &authority[..at_idx]; // Discarded!
        (true, &authority[at_idx + 1..])
    } else {
        (false, authority)
    };

    if host_port.is_empty() {
        return None;
    }

    // Parse host and port, handling IPv6 bracketed notation e.g. [::1]:8080 or [2001:db8::1]
    let (host, port) = if host_port.starts_with('[') {
        if let Some(close_bracket) = host_port.find(']') {
            let ip6 = &host_port[1..close_bracket];
            let after_bracket = &host_port[close_bracket + 1..];
            let port = if let Some(colon) = after_bracket.find(':') {
                after_bracket[colon + 1..].parse::<u16>().ok()
            } else {
                default_port_for_scheme(scheme.as_deref())
            };
            (Some(ip6.to_string()), port)
        } else {
            // Malformed bracketed IPv6
            (
                Some(host_port.to_string()),
                default_port_for_scheme(scheme.as_deref()),
            )
        }
    } else if let Some(colon_idx) = host_port.rfind(':') {
        let possible_host = &host_port[..colon_idx];
        let possible_port = &host_port[colon_idx + 1..];
        if let Ok(p) = possible_port.parse::<u16>() {
            (Some(possible_host.to_string()), Some(p))
        } else {
            // Might be an unbracketed IPv6 address or invalid port
            (
                Some(host_port.to_string()),
                default_port_for_scheme(scheme.as_deref()),
            )
        }
    } else {
        (
            Some(host_port.to_string()),
            default_port_for_scheme(scheme.as_deref()),
        )
    };

    Some((proxy_type, scheme, host, port, has_auth))
}

fn default_port_for_scheme(scheme: Option<&str>) -> Option<u16> {
    match scheme {
        Some("http") => Some(80),
        Some("https") => Some(443),
        Some("socks5") | Some("socks5h") | Some("socks4") | Some("socks4a") => Some(1080),
        _ => None,
    }
}

/// Parse comma or semicolon separated bypass list into clean tokens
pub fn parse_bypass_list(raw: &str) -> Vec<String> {
    raw.split([',', ';', ' ', '\n', '\r'])
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

/// Collect proxy configurations from environment variables
pub fn collect_environment_proxies() -> Vec<NormalizedProxyRecord> {
    let mut records = Vec::new();

    // Check NO_PROXY / no_proxy
    let bypass_raw = std::env::var("NO_PROXY")
        .or_else(|_| std::env::var("no_proxy"))
        .unwrap_or_default();
    let bypass_list = parse_bypass_list(&bypass_raw);

    let env_candidates = [
        ("HTTP_PROXY", "http"),
        ("http_proxy", "http"),
        ("HTTPS_PROXY", "https"),
        ("https_proxy", "https"),
        ("ALL_PROXY", "socks5"),
        ("all_proxy", "socks5"),
    ];

    let mut seen = std::collections::HashSet::new();

    for (var_name, default_type) in env_candidates {
        if let Ok(val) = std::env::var(var_name) {
            let val = val.trim();
            if val.is_empty() || seen.contains(val) {
                continue;
            }
            seen.insert(val.to_string());

            if let Some((proxy_type, scheme, host, port, auth)) =
                parse_proxy_endpoint(val, default_type)
            {
                records.push(NormalizedProxyRecord::new(
                    proxy_type,
                    scheme,
                    host,
                    port,
                    true,
                    format!("environment:{}", var_name),
                    bypass_list.clone(),
                    auth,
                ));
            }
        }
    }

    records
}

/// Collect Windows-specific proxy settings (WinHTTP and WinINET)
#[cfg(target_os = "windows")]
pub fn collect_windows_proxies() -> Vec<NormalizedProxyRecord> {
    let mut records = Vec::new();

    // 1. WinHTTP proxy via `netsh winhttp show proxy`
    if let Ok(output) = std::process::Command::new("netsh")
        .args(["winhttp", "show", "proxy"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains("Direct access (no proxy server)") {
            records.push(NormalizedProxyRecord::new(
                "direct",
                None,
                None,
                None,
                false,
                "winhttp",
                Vec::new(),
                false,
            ));
        } else {
            let mut proxy_servers = String::new();
            let mut bypass_list = Vec::new();

            for line in stdout.lines() {
                let trimmed = line.trim();
                if let Some(stripped) = trimmed.strip_prefix("Proxy Server(s) :") {
                    proxy_servers = stripped.trim().to_string();
                } else if let Some(stripped) = trimmed.strip_prefix("Bypass List     :") {
                    bypass_list = parse_bypass_list(stripped.trim());
                }
            }

            if !proxy_servers.is_empty() {
                // Can be semicolon separated like "http=127.0.0.1:8888;https=127.0.0.1:8888" or just "127.0.0.1:8888"
                for entry in proxy_servers.split(';') {
                    let entry = entry.trim();
                    if entry.is_empty() {
                        continue;
                    }
                    let (default_type, endpoint) = if let Some(idx) = entry.find('=') {
                        (&entry[..idx], &entry[idx + 1..])
                    } else {
                        ("http", entry)
                    };
                    if let Some((proxy_type, scheme, host, port, auth)) =
                        parse_proxy_endpoint(endpoint, default_type)
                    {
                        records.push(NormalizedProxyRecord::new(
                            proxy_type,
                            scheme,
                            host,
                            port,
                            true,
                            "winhttp",
                            bypass_list.clone(),
                            auth,
                        ));
                    }
                }
            }
        }
    }

    // 2. WinINET user proxy settings via PowerShell / Registry
    let ps_cmd = "Get-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' | Select-Object ProxyEnable,ProxyServer,ProxyOverride,AutoConfigURL | ConvertTo-Json -Compress";
    if let Ok(output) = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", ps_cmd])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&stdout) {
            let enabled = val.get("ProxyEnable").and_then(|v| v.as_i64()).unwrap_or(0) == 1;
            let proxy_server = val
                .get("ProxyServer")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let proxy_override = val
                .get("ProxyOverride")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let autoconfig = val
                .get("AutoConfigURL")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            let bypass = parse_bypass_list(proxy_override);

            if !autoconfig.is_empty() {
                records.push(NormalizedProxyRecord::new(
                    "pac",
                    Some("pac".to_string()),
                    Some(autoconfig.to_string()),
                    None,
                    enabled,
                    "wininet:autoconfig",
                    bypass.clone(),
                    false,
                ));
            }

            if !proxy_server.is_empty() {
                for entry in proxy_server.split(';') {
                    let entry = entry.trim();
                    if entry.is_empty() {
                        continue;
                    }
                    let (default_type, endpoint) = if let Some(idx) = entry.find('=') {
                        (&entry[..idx], &entry[idx + 1..])
                    } else {
                        ("http", entry)
                    };
                    if let Some((proxy_type, scheme, host, port, auth)) =
                        parse_proxy_endpoint(endpoint, default_type)
                    {
                        records.push(NormalizedProxyRecord::new(
                            proxy_type,
                            scheme,
                            host,
                            port,
                            enabled,
                            "wininet",
                            bypass.clone(),
                            auth,
                        ));
                    }
                }
            } else if autoconfig.is_empty() {
                records.push(NormalizedProxyRecord::new(
                    "direct", None, None, None, false, "wininet", bypass, false,
                ));
            }
        }
    }

    records
}

/// Collect Linux-specific proxy settings (desktop and system files)
#[cfg(target_os = "linux")]
pub fn collect_linux_proxies() -> Vec<NormalizedProxyRecord> {
    let mut records = Vec::new();

    // 1. GNOME proxy settings via gsettings if available
    if let Ok(output) = std::process::Command::new("gsettings")
        .args(["get", "org.gnome.system.proxy", "mode"])
        .output()
    {
        let mode = String::from_utf8_lossy(&output.stdout)
            .trim()
            .trim_matches('\'')
            .to_string();
        if !mode.is_empty() {
            let enabled = mode != "none";
            if mode == "auto" {
                if let Ok(pac_out) = std::process::Command::new("gsettings")
                    .args(["get", "org.gnome.system.proxy", "autoconfig-url"])
                    .output()
                {
                    let url = String::from_utf8_lossy(&pac_out.stdout)
                        .trim()
                        .trim_matches('\'')
                        .to_string();
                    records.push(NormalizedProxyRecord::new(
                        "pac",
                        Some("pac".to_string()),
                        Some(url),
                        None,
                        true,
                        "gnome",
                        Vec::new(),
                        false,
                    ));
                }
            } else if mode == "manual" {
                let protocols = [("http", "http"), ("https", "https"), ("socks", "socks5")];
                for (proto, p_type) in protocols {
                    let host_res = std::process::Command::new("gsettings")
                        .args(["get", &format!("org.gnome.system.proxy.{}", proto), "host"])
                        .output();
                    let port_res = std::process::Command::new("gsettings")
                        .args(["get", &format!("org.gnome.system.proxy.{}", proto), "port"])
                        .output();

                    if let (Ok(h_out), Ok(p_out)) = (host_res, port_res) {
                        let host = String::from_utf8_lossy(&h_out.stdout)
                            .trim()
                            .trim_matches('\'')
                            .to_string();
                        let port = String::from_utf8_lossy(&p_out.stdout)
                            .trim()
                            .parse::<u16>()
                            .ok();
                        if !host.is_empty() {
                            records.push(NormalizedProxyRecord::new(
                                p_type,
                                Some(proto.to_string()),
                                Some(host),
                                port,
                                enabled,
                                "gnome",
                                Vec::new(),
                                false,
                            ));
                        }
                    }
                }
            }
        }
    }

    // 2. /etc/environment
    if let Ok(content) = std::fs::read_to_string("/etc/environment") {
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with('#') || !line.contains('=') {
                continue;
            }
            let mut parts = line.splitn(2, '=');
            if let (Some(k), Some(v)) = (parts.next(), parts.next()) {
                let k = k.trim();
                let v = v.trim().trim_matches('"').trim_matches('\'');
                if k.eq_ignore_ascii_case("http_proxy")
                    || k.eq_ignore_ascii_case("https_proxy")
                    || k.eq_ignore_ascii_case("all_proxy")
                {
                    if let Some((proxy_type, scheme, host, port, auth)) =
                        parse_proxy_endpoint(v, "http")
                    {
                        records.push(NormalizedProxyRecord::new(
                            proxy_type,
                            scheme,
                            host,
                            port,
                            true,
                            "system:/etc/environment",
                            Vec::new(),
                            auth,
                        ));
                    }
                }
            }
        }
    }

    records
}

/// Master function to collect all available proxy configuration evidence
pub fn collect_proxy_configuration() -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let mut all_records = Vec::new();

    // 1. Environment variables (cross-platform)
    all_records.extend(collect_environment_proxies());

    // 2. OS-specific configuration
    #[cfg(target_os = "windows")]
    {
        all_records.extend(collect_windows_proxies());
    }

    #[cfg(target_os = "linux")]
    {
        all_records.extend(collect_linux_proxies());
    }

    if all_records.is_empty() {
        all_records.push(NormalizedProxyRecord::new(
            "direct",
            None,
            None,
            None,
            false,
            "system_default",
            Vec::new(),
            false,
        ));
    }

    Ok(all_records.into_iter().map(|r| r.to_json()).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_http_proxy() {
        let (pt, scheme, host, port, auth) =
            parse_proxy_endpoint("http://proxy.corp.internal:8080", "http").unwrap();
        assert_eq!(pt, "http");
        assert_eq!(scheme, Some("http".to_string()));
        assert_eq!(host, Some("proxy.corp.internal".to_string()));
        assert_eq!(port, Some(8080));
        assert!(!auth);
    }

    #[test]
    fn test_parse_https_proxy() {
        let (pt, scheme, host, port, auth) =
            parse_proxy_endpoint("https://secure-proxy.net:8443", "https").unwrap();
        assert_eq!(pt, "https");
        assert_eq!(scheme, Some("https".to_string()));
        assert_eq!(host, Some("secure-proxy.net".to_string()));
        assert_eq!(port, Some(8443));
        assert!(!auth);
    }

    #[test]
    fn test_parse_socks5_proxy() {
        let (pt, scheme, host, port, auth) =
            parse_proxy_endpoint("socks5://127.0.0.1:1080", "socks5").unwrap();
        assert_eq!(pt, "socks5");
        assert_eq!(scheme, Some("socks5".to_string()));
        assert_eq!(host, Some("127.0.0.1".to_string()));
        assert_eq!(port, Some(1080));
        assert!(!auth);
    }

    #[test]
    fn test_credential_redaction_and_auth_detection() {
        // SECURITY REQUIREMENT: Never expose password or token
        let secret = "super_secret_p@ssw0rd!";
        let raw = format!("http://admin:{}@gateway.corp.com:3128", secret);
        let (pt, scheme, host, port, auth) = parse_proxy_endpoint(&raw, "http").unwrap();

        assert_eq!(pt, "http");
        assert_eq!(scheme, Some("http".to_string()));
        assert_eq!(host, Some("gateway.corp.com".to_string()));
        assert_eq!(port, Some(3128));
        assert!(auth, "Authentication must be detected as true");

        // Verify secret does NOT appear anywhere in the parsed struct
        let record = NormalizedProxyRecord::new(pt, scheme, host, port, true, "test", vec![], auth);
        let json_str = record.to_json().to_string();
        assert!(!json_str.contains("admin"), "Username must not leak");
        assert!(!json_str.contains(secret), "Password must not leak");
        assert!(json_str.contains("\"authentication_configured\":true"));
    }

    #[test]
    fn test_ipv4_and_ipv6_parsing() {
        // IPv4
        let (_, _, host4, port4, _) = parse_proxy_endpoint("192.168.1.100:8000", "http").unwrap();
        assert_eq!(host4, Some("192.168.1.100".to_string()));
        assert_eq!(port4, Some(8000));

        // Bracketed IPv6 with port
        let (_, _, host6, port6, _) =
            parse_proxy_endpoint("http://[2001:db8::1]:9090", "http").unwrap();
        assert_eq!(host6, Some("2001:db8::1".to_string()));
        assert_eq!(port6, Some(9090));

        // Bracketed IPv6 localhost
        let (_, _, host6_local, port6_local, _) =
            parse_proxy_endpoint("[::1]:8888", "http").unwrap();
        assert_eq!(host6_local, Some("::1".to_string()));
        assert_eq!(port6_local, Some(8888));
    }

    #[test]
    fn test_no_proxy_bypass_list_parsing() {
        let bypass = parse_bypass_list("localhost, 127.0.0.1; .corp.internal\n10.0.0.0/8");
        assert_eq!(
            bypass,
            vec!["localhost", "127.0.0.1", ".corp.internal", "10.0.0.0/8"]
        );
    }

    #[test]
    fn test_malformed_proxy_urls() {
        assert!(parse_proxy_endpoint("", "http").is_none());
        assert!(parse_proxy_endpoint("   ", "http").is_none());

        // Graceful handling without panics
        let res = parse_proxy_endpoint("http://", "http");
        assert!(res.is_none());

        let res2 = parse_proxy_endpoint("http://invalid-host-with-bad-port:notaport", "http");
        assert!(res2.is_some());
    }

    #[test]
    fn test_collect_proxy_configuration_runs_without_panicking() {
        let res = collect_proxy_configuration();
        assert!(res.is_ok());
        let records = res.unwrap();
        assert!(
            !records.is_empty(),
            "Must return at least one normalized record"
        );
        assert_eq!(records[0]["collector"], "proxy");
        assert_eq!(records[0]["artifact_type"], "proxy_configuration");
    }
}
