//! Polymorphic capability architecture for JOCKY
//!
//! Provides trait-based polymorphic dispatch, platform resolution, and target constraint
//! enforcement across Windows, Linux, and cross-compilation targets.
//!
//! Complies with Section 5 requirements:
//! - Type safe
//! - Deterministic compilation and dispatch
//! - Authoritative capability checks
//! - Trait-based contracts and concrete platform collectors
//! - Enums for closed-world dispatch where appropriate
//! - Full error handling for unsupported targets and target mismatches

use crate::{CapabilityRegistry, Platform};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TargetArch {
    X64,
    Arm64,
    X86,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolymorphicResolutionError {
    #[error("Capability '{capability_id}' is not supported on target platform '{target:?}'")]
    UnsupportedPlatform {
        capability_id: String,
        target: Platform,
    },
    #[error("Target platform mismatch: collector '{collector}' requires '{expected:?}' but requested '{actual:?}'")]
    TargetMismatch {
        collector: String,
        expected: Platform,
        actual: Platform,
    },
    #[error("Unknown or unregistered capability: '{0}'")]
    UnknownCapability(String),
}

/// Root trait for all polymorphic forensic collectors
pub trait ForensicCollector: Send + Sync + std::fmt::Debug {
    /// Canonical capability identifier (e.g. "network.firewall", "network.proxy")
    fn capability_id(&self) -> &'static str;

    /// Human readable collector name
    fn name(&self) -> &'static str;

    /// The target platform this collector implementation is engineered for
    fn target_platform(&self) -> Platform;

    /// Supported target architecture, or None if architecture-agnostic
    fn target_arch(&self) -> Option<TargetArch> {
        None
    }

    /// Check if this concrete collector is compatible with requested target
    fn is_supported_on(&self, platform: Platform, arch: Option<TargetArch>) -> bool {
        let plat_ok = matches!(
            (self.target_platform(), platform),
            (Platform::Both, _)
                | (Platform::Windows, Platform::Windows)
                | (Platform::Linux, Platform::Linux)
        );
        let arch_ok = match (self.target_arch(), arch) {
            (None, _) => true,
            (Some(a1), Some(a2)) => a1 == a2,
            (Some(_), None) => true,
        };
        plat_ok && arch_ok
    }

    /// Execute collection and produce normalized JSON evidence records
    fn collect(&self) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>>;
}

// ============================================================================
// Specialized Collector Traits
// ============================================================================

pub trait FirewallCollectorTrait: ForensicCollector {
    fn collect_firewall(&self) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
        self.collect()
    }
}

pub trait ProxyCollectorTrait: ForensicCollector {
    fn collect_proxy(&self) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
        self.collect()
    }
}

pub trait NetworkCollectorTrait: ForensicCollector {
    fn collect_network(&self) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
        self.collect()
    }
}

// ============================================================================
// Concrete Platform Implementations
// ============================================================================

/// Windows Firewall Collector
#[derive(Debug, Default, Clone)]
pub struct WindowsFirewallCollector;

impl ForensicCollector for WindowsFirewallCollector {
    fn capability_id(&self) -> &'static str {
        "network.firewall"
    }

    fn name(&self) -> &'static str {
        "Windows Firewall Collector (NetSecurity/PowerShell)"
    }

    fn target_platform(&self) -> Platform {
        Platform::Windows
    }

    fn collect(&self) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
        #[cfg(target_os = "windows")]
        {
            jocky_runtime_network::firewall::collect_firewall_policy()
        }
        #[cfg(not(target_os = "windows"))]
        {
            Ok(vec![
                jocky_runtime_network::firewall::NormalizedFirewallRecord::unsupported(
                    "windows-on-non-windows-host",
                )
                .to_json(),
            ])
        }
    }
}

impl FirewallCollectorTrait for WindowsFirewallCollector {}

/// Linux Firewall Collector
#[derive(Debug, Default, Clone)]
pub struct LinuxFirewallCollector;

impl ForensicCollector for LinuxFirewallCollector {
    fn capability_id(&self) -> &'static str {
        "network.firewall"
    }

    fn name(&self) -> &'static str {
        "Linux Firewall Collector (nftables/iptables/ufw)"
    }

    fn target_platform(&self) -> Platform {
        Platform::Linux
    }

    fn collect(&self) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
        #[cfg(target_os = "linux")]
        {
            jocky_runtime_network::firewall::collect_firewall_policy()
        }
        #[cfg(not(target_os = "linux"))]
        {
            Ok(vec![
                jocky_runtime_network::firewall::NormalizedFirewallRecord::unsupported(
                    "linux-on-non-linux-host",
                )
                .to_json(),
            ])
        }
    }
}

impl FirewallCollectorTrait for LinuxFirewallCollector {}

/// Windows Proxy Collector
#[derive(Debug, Default, Clone)]
pub struct WindowsProxyCollector;

impl ForensicCollector for WindowsProxyCollector {
    fn capability_id(&self) -> &'static str {
        "network.proxy"
    }

    fn name(&self) -> &'static str {
        "Windows Proxy Collector (WinHTTP/WinINET/Registry)"
    }

    fn target_platform(&self) -> Platform {
        Platform::Windows
    }

    fn collect(&self) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
        #[cfg(target_os = "windows")]
        {
            jocky_runtime_network::proxy::collect_proxy_configuration()
        }
        #[cfg(not(target_os = "windows"))]
        {
            Ok(vec![
                jocky_runtime_network::proxy::NormalizedProxyRecord::new(
                    "direct",
                    None,
                    None,
                    None,
                    false,
                    "windows_proxy_unsupported_on_non_windows",
                    vec![],
                    false,
                )
                .to_json(),
            ])
        }
    }
}

impl ProxyCollectorTrait for WindowsProxyCollector {}

/// Linux Proxy Collector
#[derive(Debug, Default, Clone)]
pub struct LinuxProxyCollector;

impl ForensicCollector for LinuxProxyCollector {
    fn capability_id(&self) -> &'static str {
        "network.proxy"
    }

    fn name(&self) -> &'static str {
        "Linux Proxy Collector (Environment/Desktop/System)"
    }

    fn target_platform(&self) -> Platform {
        Platform::Linux
    }

    fn collect(&self) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
        #[cfg(target_os = "linux")]
        {
            jocky_runtime_network::proxy::collect_proxy_configuration()
        }
        #[cfg(not(target_os = "linux"))]
        {
            Ok(vec![
                jocky_runtime_network::proxy::NormalizedProxyRecord::new(
                    "direct",
                    None,
                    None,
                    None,
                    false,
                    "linux_proxy_unsupported_on_non_linux",
                    vec![],
                    false,
                )
                .to_json(),
            ])
        }
    }
}

impl ProxyCollectorTrait for LinuxProxyCollector {}

/// Windows Network Collector
#[derive(Debug, Default, Clone)]
pub struct WindowsNetworkCollector;

impl ForensicCollector for WindowsNetworkCollector {
    fn capability_id(&self) -> &'static str {
        "network.connections"
    }

    fn name(&self) -> &'static str {
        "Windows Network Connection Enumerator"
    }

    fn target_platform(&self) -> Platform {
        Platform::Windows
    }

    fn collect(&self) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
        jocky_runtime_network::enumerate_connections()
    }
}

impl NetworkCollectorTrait for WindowsNetworkCollector {}

/// Linux Network Collector
#[derive(Debug, Default, Clone)]
pub struct LinuxNetworkCollector;

impl ForensicCollector for LinuxNetworkCollector {
    fn capability_id(&self) -> &'static str {
        "network.connections"
    }

    fn name(&self) -> &'static str {
        "Linux Network Connection Enumerator"
    }

    fn target_platform(&self) -> Platform {
        Platform::Linux
    }

    fn collect(&self) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
        jocky_runtime_network::enumerate_connections()
    }
}

impl NetworkCollectorTrait for LinuxNetworkCollector {}

// ============================================================================
// Closed-World Enum for Zero-Cost Dispatch
// ============================================================================

pub enum DynamicCollector {
    WindowsFirewall(WindowsFirewallCollector),
    LinuxFirewall(LinuxFirewallCollector),
    WindowsProxy(WindowsProxyCollector),
    LinuxProxy(LinuxProxyCollector),
    WindowsNetwork(WindowsNetworkCollector),
    LinuxNetwork(LinuxNetworkCollector),
}

impl DynamicCollector {
    pub fn collect(&self) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
        match self {
            Self::WindowsFirewall(c) => c.collect(),
            Self::LinuxFirewall(c) => c.collect(),
            Self::WindowsProxy(c) => c.collect(),
            Self::LinuxProxy(c) => c.collect(),
            Self::WindowsNetwork(c) => c.collect(),
            Self::LinuxNetwork(c) => c.collect(),
        }
    }

    pub fn capability_id(&self) -> &'static str {
        match self {
            Self::WindowsFirewall(c) => c.capability_id(),
            Self::LinuxFirewall(c) => c.capability_id(),
            Self::WindowsProxy(c) => c.capability_id(),
            Self::LinuxProxy(c) => c.capability_id(),
            Self::WindowsNetwork(c) => c.capability_id(),
            Self::LinuxNetwork(c) => c.capability_id(),
        }
    }

    pub fn target_platform(&self) -> Platform {
        match self {
            Self::WindowsFirewall(c) => c.target_platform(),
            Self::LinuxFirewall(c) => c.target_platform(),
            Self::WindowsProxy(c) => c.target_platform(),
            Self::LinuxProxy(c) => c.target_platform(),
            Self::WindowsNetwork(c) => c.target_platform(),
            Self::LinuxNetwork(c) => c.target_platform(),
        }
    }
}

// ============================================================================
// Authoritative Polymorphic Resolver
// ============================================================================

pub struct PolymorphicResolver;

impl PolymorphicResolver {
    /// Resolve a Firewall collector for the requested target platform
    pub fn resolve_firewall(
        target: Platform,
    ) -> Result<Box<dyn FirewallCollectorTrait>, PolymorphicResolutionError> {
        match target {
            Platform::Windows => Ok(Box::new(WindowsFirewallCollector)),
            Platform::Linux => Ok(Box::new(LinuxFirewallCollector)),
            Platform::Both => {
                #[cfg(target_os = "windows")]
                {
                    Ok(Box::new(WindowsFirewallCollector))
                }
                #[cfg(not(target_os = "windows"))]
                {
                    Ok(Box::new(LinuxFirewallCollector))
                }
            }
        }
    }

    /// Resolve a Proxy collector for the requested target platform
    pub fn resolve_proxy(
        target: Platform,
    ) -> Result<Box<dyn ProxyCollectorTrait>, PolymorphicResolutionError> {
        match target {
            Platform::Windows => Ok(Box::new(WindowsProxyCollector)),
            Platform::Linux => Ok(Box::new(LinuxProxyCollector)),
            Platform::Both => {
                #[cfg(target_os = "windows")]
                {
                    Ok(Box::new(WindowsProxyCollector))
                }
                #[cfg(not(target_os = "windows"))]
                {
                    Ok(Box::new(LinuxProxyCollector))
                }
            }
        }
    }

    /// Resolve a Network collector for the requested target platform
    pub fn resolve_network(
        target: Platform,
    ) -> Result<Box<dyn NetworkCollectorTrait>, PolymorphicResolutionError> {
        match target {
            Platform::Windows => Ok(Box::new(WindowsNetworkCollector)),
            Platform::Linux => Ok(Box::new(LinuxNetworkCollector)),
            Platform::Both => {
                #[cfg(target_os = "windows")]
                {
                    Ok(Box::new(WindowsNetworkCollector))
                }
                #[cfg(not(target_os = "windows"))]
                {
                    Ok(Box::new(LinuxNetworkCollector))
                }
            }
        }
    }

    /// Resolve any collector by canonical capability ID and target platform
    pub fn resolve_collector(
        capability_id: &str,
        target: Platform,
        arch: Option<TargetArch>,
    ) -> Result<Box<dyn ForensicCollector>, PolymorphicResolutionError> {
        // Verify capability existence in authoritative registry
        let registry = CapabilityRegistry::new();
        let cap = registry.get(capability_id).ok_or_else(|| {
            PolymorphicResolutionError::UnknownCapability(capability_id.to_string())
        })?;

        // Check if capability itself is supported on the target platform
        let is_compat = matches!(
            (cap.platforms, target),
            (Platform::Both, _)
                | (Platform::Windows, Platform::Windows)
                | (Platform::Linux, Platform::Linux)
        );

        if !is_compat {
            return Err(PolymorphicResolutionError::UnsupportedPlatform {
                capability_id: capability_id.to_string(),
                target,
            });
        }

        // Return concrete polymorphic collector
        let collector: Box<dyn ForensicCollector> = match capability_id {
            "network.firewall" | "network.firewall.policy" | "security.firewall" => match target {
                Platform::Windows => Box::new(WindowsFirewallCollector),
                Platform::Linux => Box::new(LinuxFirewallCollector),
                Platform::Both => {
                    #[cfg(target_os = "windows")]
                    {
                        Box::new(WindowsFirewallCollector)
                    }
                    #[cfg(not(target_os = "windows"))]
                    {
                        Box::new(LinuxFirewallCollector)
                    }
                }
            },
            "network.proxy" => match target {
                Platform::Windows => Box::new(WindowsProxyCollector),
                Platform::Linux => Box::new(LinuxProxyCollector),
                Platform::Both => {
                    #[cfg(target_os = "windows")]
                    {
                        Box::new(WindowsProxyCollector)
                    }
                    #[cfg(not(target_os = "windows"))]
                    {
                        Box::new(LinuxProxyCollector)
                    }
                }
            },
            "network.connections" | "network.listening" => match target {
                Platform::Windows => Box::new(WindowsNetworkCollector),
                Platform::Linux => Box::new(LinuxNetworkCollector),
                Platform::Both => {
                    #[cfg(target_os = "windows")]
                    {
                        Box::new(WindowsNetworkCollector)
                    }
                    #[cfg(not(target_os = "windows"))]
                    {
                        Box::new(LinuxNetworkCollector)
                    }
                }
            },
            _ => {
                // If it's another capability in registry, resolve to generic executor
                Box::new(GenericPolymorphicCollector {
                    cap_id: cap.id.clone(),
                    name: cap.name.clone(),
                    platform: cap.platforms,
                })
            }
        };

        if !collector.is_supported_on(target, arch) {
            return Err(PolymorphicResolutionError::TargetMismatch {
                collector: collector.name().to_string(),
                expected: collector.target_platform(),
                actual: target,
            });
        }

        Ok(collector)
    }
}

/// Generic collector adapter for registry-registered capabilities
#[derive(Debug)]
struct GenericPolymorphicCollector {
    cap_id: String,
    name: String,
    platform: Platform,
}

impl ForensicCollector for GenericPolymorphicCollector {
    fn capability_id(&self) -> &'static str {
        // Leaked for static lifetime in generic fallback adapter
        Box::leak(self.cap_id.clone().into_boxed_str())
    }

    fn name(&self) -> &'static str {
        Box::leak(self.name.clone().into_boxed_str())
    }

    fn target_platform(&self) -> Platform {
        self.platform
    }

    fn collect(&self) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
        let registry = CapabilityRegistry::new();
        let res = registry
            .invoke_runtime_capability(&self.cap_id)
            .map_err(Box::<dyn std::error::Error>::from)?;
        Ok(res.evidence_records)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_polymorphic_trait_contract() {
        let win_fw = WindowsFirewallCollector;
        assert_eq!(win_fw.capability_id(), "network.firewall");
        assert_eq!(win_fw.target_platform(), Platform::Windows);
        assert!(win_fw.is_supported_on(Platform::Windows, None));
        assert!(!win_fw.is_supported_on(Platform::Linux, None));

        let lin_fw = LinuxFirewallCollector;
        assert_eq!(lin_fw.capability_id(), "network.firewall");
        assert_eq!(lin_fw.target_platform(), Platform::Linux);
        assert!(lin_fw.is_supported_on(Platform::Linux, None));
        assert!(!lin_fw.is_supported_on(Platform::Windows, None));
    }

    #[test]
    fn test_windows_implementation_selection() {
        let fw = PolymorphicResolver::resolve_firewall(Platform::Windows).unwrap();
        assert_eq!(fw.target_platform(), Platform::Windows);
        assert_eq!(fw.capability_id(), "network.firewall");

        let proxy = PolymorphicResolver::resolve_proxy(Platform::Windows).unwrap();
        assert_eq!(proxy.target_platform(), Platform::Windows);
        assert_eq!(proxy.capability_id(), "network.proxy");
    }

    #[test]
    fn test_linux_implementation_selection() {
        let fw = PolymorphicResolver::resolve_firewall(Platform::Linux).unwrap();
        assert_eq!(fw.target_platform(), Platform::Linux);
        assert_eq!(fw.capability_id(), "network.firewall");

        let proxy = PolymorphicResolver::resolve_proxy(Platform::Linux).unwrap();
        assert_eq!(proxy.target_platform(), Platform::Linux);
        assert_eq!(proxy.capability_id(), "network.proxy");
    }

    #[test]
    fn test_unsupported_target_rejection() {
        // Registry capability that is Windows-only: auth.windows.logon
        let res =
            PolymorphicResolver::resolve_collector("auth.windows.logon", Platform::Linux, None);
        assert!(res.is_err());
        match res.unwrap_err() {
            PolymorphicResolutionError::UnsupportedPlatform {
                capability_id,
                target,
            } => {
                assert_eq!(capability_id, "auth.windows.logon");
                assert_eq!(target, Platform::Linux);
            }
            other => panic!("Expected UnsupportedPlatform, got: {:?}", other),
        }
    }

    #[test]
    fn test_unknown_capability_rejection() {
        let res = PolymorphicResolver::resolve_collector(
            "nonexistent.capability.id",
            Platform::Windows,
            None,
        );
        assert!(res.is_err());
        match res.unwrap_err() {
            PolymorphicResolutionError::UnknownCapability(id) => {
                assert_eq!(id, "nonexistent.capability.id");
            }
            other => panic!("Expected UnknownCapability, got: {:?}", other),
        }
    }

    #[test]
    fn test_deterministic_dispatch() {
        let c1 =
            PolymorphicResolver::resolve_collector("network.firewall", Platform::Windows, None)
                .unwrap();
        let c2 =
            PolymorphicResolver::resolve_collector("network.firewall", Platform::Windows, None)
                .unwrap();
        assert_eq!(c1.capability_id(), c2.capability_id());
        assert_eq!(c1.name(), c2.name());
        assert_eq!(c1.target_platform(), c2.target_platform());
    }

    #[test]
    fn test_closed_world_dynamic_collector_enum() {
        let dc = DynamicCollector::WindowsFirewall(WindowsFirewallCollector);
        assert_eq!(dc.capability_id(), "network.firewall");
        assert_eq!(dc.target_platform(), Platform::Windows);

        let dl = DynamicCollector::LinuxProxy(LinuxProxyCollector);
        assert_eq!(dl.capability_id(), "network.proxy");
        assert_eq!(dl.target_platform(), Platform::Linux);
    }
}
