//! jockey Runtime - Network connection enumeration

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
    pub protocol: String, // tcp, udp, tcp6, udp6
    pub local_address: IpAddr,
    pub local_port: u16,
    pub remote_address: IpAddr,
    pub remote_port: u16,
    pub state: String, // LISTEN, ESTABLISHED, TIME_WAIT, etc.
    pub pid: Option<u32>,
    pub process_name: Option<String>,
}

pub fn enumerate_connections() -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    #[cfg(target_os = "linux")]
    {
        use netstat2::{get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo};

        let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
        let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;

        let sockets = get_sockets_info(af_flags, proto_flags)?;
        let mut results = Vec::new();

        for socket in sockets {
            let (protocol, local_addr, local_port, remote_addr, remote_port, state, pid) =
                match socket.protocol_socket_info {
                    ProtocolSocketInfo::Tcp(tcp) => (
                        "tcp",
                        tcp.local_addr,
                        tcp.local_port,
                        tcp.remote_addr,
                        tcp.remote_port,
                        format!("{:?}", tcp.state),
                        socket.associated_pids.first().copied(),
                    ),
                    ProtocolSocketInfo::Udp(udp) => (
                        "udp",
                        udp.local_addr,
                        udp.local_port,
                        udp.local_addr,
                        0,
                        "UNCONNECTED".to_string(),
                        socket.associated_pids.first().copied(),
                    ),
                };

            let conn = NetworkConnection {
                protocol: protocol.to_string(),
                local_address: local_addr,
                local_port,
                remote_address: remote_addr,
                remote_port,
                state,
                pid,
                process_name: pid.and_then(_get_process_name),
            };

            results.push(serde_json::to_value(conn)?);
        }

        Ok(results)
    }

    #[cfg(target_os = "windows")]
    {
        let mut results = Vec::new();
        let tcp_output = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", "Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess | ConvertTo-Json -Compress"])
            .output();

        if let Ok(output) = tcp_output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Ok(serde_json::Value::Array(items)) =
                serde_json::from_str::<serde_json::Value>(&stdout)
            {
                for item in items {
                    if let Some(map) = item.as_object() {
                        results.push(serde_json::json!({
                            "protocol": "tcp",
                            "local_address": map.get("LocalAddress").and_then(|v| v.as_str()).unwrap_or("0.0.0.0"),
                            "local_port": map.get("LocalPort").and_then(|v| v.as_u64()).unwrap_or(0) as u16,
                            "remote_address": map.get("RemoteAddress").and_then(|v| v.as_str()).unwrap_or("0.0.0.0"),
                            "remote_port": map.get("RemotePort").and_then(|v| v.as_u64()).unwrap_or(0) as u16,
                            "state": map.get("State").and_then(|v| v.as_str()).unwrap_or("UNKNOWN"),
                            "pid": map.get("OwningProcess").and_then(|v| v.as_u64()).map(|v| v as u32),
                            "process_name": None::<String>
                        }));
                    }
                }
            }
        }

        let udp_output = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", "Get-NetUDPEndpoint | Select-Object LocalAddress,LocalPort,OwningProcess | ConvertTo-Json -Compress"])
            .output();
        if let Ok(output) = udp_output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(&stdout) {
                let items = match value {
                    serde_json::Value::Array(items) => items,
                    serde_json::Value::Object(item) => vec![serde_json::Value::Object(item)],
                    _ => Vec::new(),
                };
                for item in items {
                    if let Some(map) = item.as_object() {
                        results.push(serde_json::json!({
                            "protocol": "udp",
                            "local_address": map.get("LocalAddress").and_then(|v| v.as_str()).unwrap_or("0.0.0.0"),
                            "local_port": map.get("LocalPort").and_then(|v| v.as_u64()).unwrap_or(0) as u16,
                            "remote_address": "0.0.0.0",
                            "remote_port": 0,
                            "state": "UNCONNECTED",
                            "pid": map.get("OwningProcess").and_then(|v| v.as_u64()).map(|v| v as u32),
                            "process_name": None::<String>
                        }));
                    }
                }
            }
        }
        Ok(results)
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Ok(Vec::new())
    }
}

/// Enumerate network interfaces
pub fn enumerate_interfaces() -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    #[cfg(target_os = "linux")]
    {
        use std::fs;
        let mut results = Vec::new();

        if let Ok(net_dir) = fs::read_dir("/sys/class/net") {
            for entry in net_dir.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name == "lo" {
                    continue;
                }

                let mac_address = fs::read_to_string(format!("/sys/class/net/{}/address", name))
                    .ok()
                    .map(|s| s.trim().to_string());
                let mtu = fs::read_to_string(format!("/sys/class/net/{}/mtu", name))
                    .ok()
                    .and_then(|s| s.trim().parse::<u32>().ok());
                let flags = fs::read_to_string(format!("/sys/class/net/{}/flags", name))
                    .ok()
                    .map(|s| s.trim().to_string());
                let speed_mbps = fs::read_to_string(format!("/sys/class/net/{}/speed", name))
                    .ok()
                    .and_then(|s| s.trim().parse::<u64>().ok());
                let driver = fs::read_to_string(format!(
                    "/sys/class/net/{}/device/driver/module/name",
                    name
                ))
                .ok()
                .map(|s| s.trim().to_string());

                // Get IP addresses
                let (ipv4_addresses, ipv6_addresses) = get_interface_ips(&name);

                results.push(serde_json::json!({
                    "name": name,
                    "mac_address": mac_address,
                    "ipv4_addresses": ipv4_addresses,
                    "ipv6_addresses": ipv6_addresses,
                    "mtu": mtu,
                    "flags": flags.map(|f| vec![f]).unwrap_or_default(),
                    "speed_mbps": speed_mbps,
                    "driver": driver,
                }));
            }
        }
        Ok(results)
    }

    #[cfg(target_os = "windows")]
    {
        let mut results = Vec::new();
        let output = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", "Get-NetAdapter | Where-Object {$_.Status -ne 'Disconnected'} | Select-Object Name,MacAddress,InterfaceDescription,LinkSpeed | ConvertTo-Json -Compress"])
            .output();

        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&stdout) {
                let items: Vec<serde_json::Value> = match val {
                    serde_json::Value::Array(arr) => arr,
                    serde_json::Value::Object(_) => vec![val],
                    _ => vec![],
                };
                for item in items {
                    results.push(serde_json::json!({
                        "name": item.get("Name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        "mac_address": item.get("MacAddress").and_then(|v| v.as_str()).map(|s| s.to_string()),
                        "ipv4_addresses": Vec::<String>::new(),
                        "ipv6_addresses": Vec::<String>::new(),
                        "mtu": None::<u32>,
                        "flags": Vec::<String>::new(),
                        "speed_mbps": item.get("LinkSpeed").and_then(|v| v.as_u64()).map(|s| s / 1_000_000),
                        "driver": item.get("InterfaceDescription").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    }));
                }
            }
        }
        Ok(results)
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Ok(Vec::new())
    }
}

/// Enumerate routing table
pub fn enumerate_routes() -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    #[cfg(target_os = "linux")]
    {
        use std::process::Command;
        let mut results = Vec::new();

        if let Ok(output) = Command::new("ip").args(["route", "show"]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    let gateway = parts
                        .iter()
                        .position(|&p| p == "via")
                        .and_then(|i| parts.get(i + 1))
                        .copied()
                        .unwrap_or("");
                    let interface = parts
                        .iter()
                        .position(|&p| p == "dev")
                        .and_then(|i| parts.get(i + 1))
                        .copied()
                        .unwrap_or("");
                    results.push(serde_json::json!({
                        "destination": parts[0],
                        "gateway": gateway,
                        "interface": interface,
                        "protocol": "kernel",
                        "metric": None::<u32>,
                    }));
                }
            }
        }
        Ok(results)
    }

    #[cfg(target_os = "windows")]
    {
        let mut results = Vec::new();
        let output = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", "Get-NetRoute | Select-Object DestinationPrefix,NextHop,InterfaceAlias,RouteMetric | ConvertTo-Json -Compress"])
            .output();

        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&stdout) {
                let items: Vec<serde_json::Value> = match val {
                    serde_json::Value::Array(arr) => arr,
                    serde_json::Value::Object(_) => vec![val],
                    _ => vec![],
                };
                for item in items {
                    results.push(serde_json::json!({
                        "destination": item.get("DestinationPrefix").and_then(|v| v.as_str()).unwrap_or(""),
                        "gateway": item.get("NextHop").and_then(|v| v.as_str()).unwrap_or(""),
                        "interface": item.get("InterfaceAlias").and_then(|v| v.as_str()).unwrap_or(""),
                        "protocol": "netsh",
                        "metric": item.get("RouteMetric").and_then(|v| v.as_u64()).map(|v| v as u32),
                    }));
                }
            }
        }
        Ok(results)
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Ok(Vec::new())
    }
}

/// Enumerate ARP table
pub fn enumerate_arp() -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    #[cfg(target_os = "linux")]
    {
        use std::fs;
        let mut results = Vec::new();

        if let Ok(arp_content) = fs::read_to_string("/proc/net/arp") {
            for line in arp_content.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 6 {
                    results.push(serde_json::json!({
                        "ip_address": parts[0],
                        "hw_type": parts[1],
                        "flags": parts[2],
                        "mac_address": parts[3],
                        "mask": parts[4],
                        "device": parts[5],
                    }));
                }
            }
        }
        Ok(results)
    }

    #[cfg(target_os = "windows")]
    {
        let mut results = Vec::new();
        let output = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", "Get-NetNeighbor | Select-Object IPAddress,LinkLayerAddress,InterfaceAlias,State | ConvertTo-Json -Compress"])
            .output();

        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&stdout) {
                let items: Vec<serde_json::Value> = match val {
                    serde_json::Value::Array(arr) => arr,
                    serde_json::Value::Object(_) => vec![val],
                    _ => vec![],
                };
                for item in items {
                    results.push(serde_json::json!({
                        "ip_address": item.get("IPAddress").and_then(|v| v.as_str()).unwrap_or(""),
                        "mac_address": item.get("LinkLayerAddress").and_then(|v| v.as_str()).unwrap_or(""),
                        "interface": item.get("InterfaceAlias").and_then(|v| v.as_str()).unwrap_or(""),
                        "state": item.get("State").and_then(|v| v.as_str()).unwrap_or(""),
                    }));
                }
            }
        }
        Ok(results)
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Ok(Vec::new())
    }
}

/// Enumerate DNS servers
pub fn enumerate_dns_servers() -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    #[cfg(target_os = "linux")]
    {
        use std::fs;
        let mut results = Vec::new();

        if let Ok(resolv) = fs::read_to_string("/etc/resolv.conf") {
            for line in resolv.lines() {
                if line.starts_with("nameserver") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        results.push(serde_json::json!({
                            "server": parts[1],
                            "source": "resolv.conf",
                        }));
                    }
                }
            }
        }
        Ok(results)
    }

    #[cfg(target_os = "windows")]
    {
        let mut results = Vec::new();
        let output = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", "Get-DnsClientServerAddress | Where-Object {$_.ServerAddresses} | Select-Object InterfaceAlias,ServerAddresses | ConvertTo-Json -Compress"])
            .output();

        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&stdout) {
                let items: Vec<serde_json::Value> = match val {
                    serde_json::Value::Array(arr) => arr,
                    serde_json::Value::Object(_) => vec![val],
                    _ => vec![],
                };
                for item in items {
                    if let Some(addrs) = item.get("ServerAddresses").and_then(|v| v.as_array()) {
                        for addr in addrs {
                            results.push(serde_json::json!({
                                "server": addr.as_str().unwrap_or(""),
                                "interface": item.get("InterfaceAlias").and_then(|v| v.as_str()).unwrap_or(""),
                            }));
                        }
                    }
                }
            }
        }
        Ok(results)
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Ok(Vec::new())
    }
}

/// Enumerate DNS cache
pub fn enumerate_dns_cache() -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    #[cfg(target_os = "linux")]
    {
        // Linux doesn't have a standard DNS cache accessible without systemd-resolved or nscd
        Ok(vec![serde_json::json!({
            "collector": "network",
            "artifact_type": "dns_cache",
            "status": "not_implemented",
            "note": "DNS cache enumeration requires systemd-resolved or nscd on Linux",
        })])
    }

    #[cfg(target_os = "windows")]
    {
        let mut results = Vec::new();
        let output = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", "Get-DnsClientCache | Select-Object Entry,RecordName,RecordType,RecordData,TimeToLive | ConvertTo-Json -Compress"])
            .output();

        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&stdout) {
                let items: Vec<serde_json::Value> = match val {
                    serde_json::Value::Array(arr) => arr,
                    serde_json::Value::Object(_) => vec![val],
                    _ => vec![],
                };
                for item in items {
                    results.push(serde_json::json!({
                        "name": item.get("RecordName").and_then(|v| v.as_str()).unwrap_or(""),
                        "type": item.get("RecordType").and_then(|v| v.as_u64()).unwrap_or(0),
                        "data": item.get("RecordData").and_then(|v| v.as_str()).unwrap_or(""),
                        "ttl": item.get("TimeToLive").and_then(|v| v.as_u64()).unwrap_or(0),
                    }));
                }
            }
        }
        Ok(results)
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Ok(Vec::new())
    }
}

/// Enumerate hosts file
pub fn enumerate_hosts() -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    #[cfg(target_os = "linux")]
    {
        use std::fs;
        let mut results = Vec::new();

        if let Ok(hosts) = fs::read_to_string("/etc/hosts") {
            for line in hosts.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let ip = parts[0];
                    for hostname in &parts[1..] {
                        results.push(serde_json::json!({
                            "ip_address": ip,
                            "hostname": hostname,
                        }));
                    }
                }
            }
        }
        Ok(results)
    }

    #[cfg(target_os = "windows")]
    {
        use std::fs;
        let mut results = Vec::new();

        let hosts_path = r"C:\Windows\System32\drivers\etc\hosts";
        if let Ok(hosts) = fs::read_to_string(hosts_path) {
            for line in hosts.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let ip = parts[0];
                    for hostname in &parts[1..] {
                        results.push(serde_json::json!({
                            "ip_address": ip,
                            "hostname": hostname,
                        }));
                    }
                }
            }
        }
        Ok(results)
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Ok(Vec::new())
    }
}

/// Enumerate listening ports
pub fn enumerate_listening_ports() -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    // Filter connections for LISTEN state
    let connections = enumerate_connections()?;
    let listening: Vec<_> = connections
        .into_iter()
        .filter(|c| {
            c.get("state")
                .and_then(|v| v.as_str())
                .map(|s| s.eq_ignore_ascii_case("LISTEN"))
                .unwrap_or(false)
        })
        .collect();
    Ok(listening)
}

/// Enumerate firewall policy
pub fn enumerate_firewall_policy() -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    #[cfg(target_os = "linux")]
    {
        let mut results = Vec::new();

        // Check iptables
        if let Ok(output) = std::process::Command::new("iptables")
            .args(["-L", "-n", "-v"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            results.push(serde_json::json!({
                "type": "iptables",
                "rules": stdout.lines().collect::<Vec<_>>(),
            }));
        }

        // Check nftables
        if let Ok(output) = std::process::Command::new("nft")
            .args(["list", "ruleset"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            results.push(serde_json::json!({
                "type": "nftables",
                "rules": stdout.lines().collect::<Vec<_>>(),
            }));
        }

        // Check ufw
        if let Ok(output) = std::process::Command::new("ufw")
            .args(["status", "verbose"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            results.push(serde_json::json!({
                "type": "ufw",
                "rules": stdout.lines().collect::<Vec<_>>(),
            }));
        }

        if results.is_empty() {
            results.push(serde_json::json!({
                "collector": "network",
                "artifact_type": "firewall_policy",
                "status": "not_found",
                "note": "No firewall rules found (iptables, nftables, ufw)",
            }));
        }

        Ok(results)
    }

    #[cfg(target_os = "windows")]
    {
        let mut results = Vec::new();
        let output = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", "Get-NetFirewallRule | Select-Object Name,DisplayName,Enabled,Action,Direction,Protocol,LocalPort,RemotePort,Program,Profile | ConvertTo-Json -Compress"])
            .output();

        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&stdout) {
                let items: Vec<serde_json::Value> = match val {
                    serde_json::Value::Array(arr) => arr,
                    serde_json::Value::Object(_) => vec![val],
                    _ => vec![],
                };
                for item in items {
                    results.push(serde_json::json!({
                        "name": item.get("Name").and_then(|v| v.as_str()).unwrap_or(""),
                        "display_name": item.get("DisplayName").and_then(|v| v.as_str()).unwrap_or(""),
                        "enabled": item.get("Enabled").and_then(|v| v.as_str()).unwrap_or(""),
                        "action": item.get("Action").and_then(|v| v.as_str()).unwrap_or(""),
                        "direction": item.get("Direction").and_then(|v| v.as_str()).unwrap_or(""),
                        "protocol": item.get("Protocol").and_then(|v| v.as_str()).unwrap_or(""),
                        "local_port": item.get("LocalPort").and_then(|v| v.as_str()).unwrap_or(""),
                        "remote_port": item.get("RemotePort").and_then(|v| v.as_str()).unwrap_or(""),
                        "program": item.get("Program").and_then(|v| v.as_str()).unwrap_or(""),
                        "profile": item.get("Profile").and_then(|v| v.as_str()).unwrap_or(""),
                    }));
                }
            }
        }
        Ok(results)
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Ok(Vec::new())
    }
}

/// Enumerate network shares
pub fn enumerate_shares() -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    #[cfg(target_os = "linux")]
    {
        let mut results = Vec::new();

        // Check Samba shares
        if let Ok(output) = std::process::Command::new("smbstatus")
            .args(["-S"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            results.push(serde_json::json!({
                "type": "samba",
                "shares": stdout.lines().collect::<Vec<_>>(),
            }));
        }

        // Check NFS exports
        if let Ok(exports) = std::fs::read_to_string("/etc/exports") {
            results.push(serde_json::json!({
                "type": "nfs",
                "exports": exports.lines().collect::<Vec<_>>(),
            }));
        }

        if results.is_empty() {
            results.push(serde_json::json!({
                "collector": "network",
                "artifact_type": "shares",
                "status": "not_found",
                "note": "No network shares found (Samba, NFS)",
            }));
        }

        Ok(results)
    }

    #[cfg(target_os = "windows")]
    {
        let mut results = Vec::new();
        let output = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "Get-SmbShare | Select-Object Name,Path,Description | ConvertTo-Json -Compress",
            ])
            .output();

        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&stdout) {
                let items: Vec<serde_json::Value> = match val {
                    serde_json::Value::Array(arr) => arr,
                    serde_json::Value::Object(_) => vec![val],
                    _ => vec![],
                };
                for item in items {
                    results.push(serde_json::json!({
                        "name": item.get("Name").and_then(|v| v.as_str()).unwrap_or(""),
                        "path": item.get("Path").and_then(|v| v.as_str()).unwrap_or(""),
                        "description": item.get("Description").and_then(|v| v.as_str()).unwrap_or(""),
                    }));
                }
            }
        }
        Ok(results)
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Ok(Vec::new())
    }
}

/// Enumerate suspicious listeners
pub fn enumerate_listeners() -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    // Get listening ports and flag suspicious ones
    let listening = enumerate_listening_ports()?;
    let mut results = Vec::new();

    for listener in listening {
        let port = listener
            .get("local_port")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let process = listener
            .get("process_name")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // Flag suspicious ports
        let suspicious = matches!(
            port,
            4444 | 5555 | 6666 | 7777 | 8888 | 9999 | 31337 | 12345 | 54321
        ) || process.to_lowercase().contains("nc")
            || process.to_lowercase().contains("netcat")
            || process.to_lowercase().contains("meterpreter");

        results.push(serde_json::json!({
            "listener": listener,
            "suspicious": suspicious,
            "reason": if suspicious { "Common backdoor port or suspicious process" } else { "" },
        }));
    }

    Ok(results)
}

#[allow(dead_code)]
fn get_interface_ips(interface: &str) -> (Vec<String>, Vec<String>) {
    use std::process::Command;
    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();

    if let Ok(output) = Command::new("ip")
        .args(["-4", "addr", "show", "dev", interface])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if line.contains("inet ") {
                if let Some(addr) = line.split_whitespace().nth(1) {
                    ipv4.push(addr.to_string());
                }
            }
        }
    }

    if let Ok(output) = Command::new("ip")
        .args(["-6", "addr", "show", "dev", interface])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if line.contains("inet6 ") {
                if let Some(addr) = line.split_whitespace().nth(1) {
                    ipv6.push(addr.to_string());
                }
            }
        }
    }
    (ipv4, ipv6)
}

fn _get_process_name(_pid: u32) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string(format!("/proc/{}/comm", _pid))
            .ok()
            .map(|s| s.trim().to_string())
    }

    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}
