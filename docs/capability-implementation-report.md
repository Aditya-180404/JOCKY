# Capability Inventory and Verification Status

**Updated:** 2026-09-28
**Registry source:** `runtime/capabilities/src/lib.rs`  
**Release status:** Full capability registry verified across CLI, API, Runtime, and Web IDE.

## Registry Counts

The authoritative runtime registry, CLI, and API report:

| Status | Count |
| --- | ---: |
| Total | 247 |
| Implemented | 241 |
| Requires elevation | 4 |
| Partial | 1 |
| Platform-specific | 0 |
| Unsupported | 1 |
| **Coverage** | **97.6%** |

## Newly Implemented & Hardened Capabilities

1. **Firewall (`network.firewall`, `network.firewall.policy`, `security.firewall_rules`):**
   - Implemented in `runtime/network/src/firewall.rs` and `runtime/security/src/lib.rs`.
   - Real collection on Windows via native NetSecurity APIs / PowerShell `Get-NetFirewallProfile` and `Get-NetFirewallRule`.
   - Real collection on Linux via `nftables`, `iptables` (`-S` and `iptables-save`), and `ufw`.
   - Graceful elevation failure handling returning `requires_elevation` status rather than panicking or faking empty results.
   - Normalized evidence schema: profile state, inbound/outbound default actions, rules with direction, protocol, ports, programs, services, and timestamps.
   - Comprehensive unit and integration tests passing.

2. **Proxy (`network.proxy`):**
   - Implemented in `runtime/network/src/proxy.rs`.
   - Windows proxy discovery from WinHTTP (`netsh winhttp show proxy`) and WinINET / User registry settings (`HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings`).
   - Linux discovery from `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`, `/etc/environment`, and GNOME proxy settings.
   - Strict credential redaction: userinfo / passwords / tokens are stripped; reports `authentication_configured: true` without exposing credentials.
   - Supports IPv4, IPv6 bracketed hosts, port parsing, bypass lists, PAC URLs.
   - Unit tests covering protocol variations, credential redaction, and bypass lists.

3. **Polymorphic Collector Architecture:**
   - Implemented in `runtime/capabilities/src/polymorphism.rs`.
   - Core traits: `ForensicCollector`, `FirewallCollectorTrait`, `ProxyCollectorTrait`, `NetworkCollectorTrait`.
   - Platform implementations: `WindowsFirewallCollector`, `LinuxFirewallCollector`, `WindowsProxyCollector`, `LinuxProxyCollector`, `WindowsNetworkCollector`, `LinuxNetworkCollector`.
   - `DynamicCollector` closed-world enum for dynamic runtime dispatch.
   - `PolymorphicResolver` validates capability compatibility against authoritative registry before instantiation.
   - Unit tests covering trait contracts, resolution, and platform mismatch rejection.

## Verification Performed

- `jocky capabilities` and `jocky capabilities --format json` report exactly 247 entries.
- `GET /api/compiler/capabilities` returns the authoritative capabilities envelope matching the CLI breakdown.
- Web IDE target selector and Monaco capability autocompletion consumes all 247 capabilities.
- All forensic categories (17) verified with complete metadata and privilege schemas.
