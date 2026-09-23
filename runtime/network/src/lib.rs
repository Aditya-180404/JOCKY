//! TraceForge Runtime - Network connection enumeration

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
        use netstat2::{
            get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo,
        };

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
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(&stdout) {
                match value {
                    serde_json::Value::Array(items) => {
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
                    _ => {}
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
