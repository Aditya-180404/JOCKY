//! TraceForge Runtime - Network connection enumeration

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
    pub protocol: String,      // tcp, udp, tcp6, udp6
    pub local_address: IpAddr,
    pub local_port: u16,
    pub remote_address: IpAddr,
    pub remote_port: u16,
    pub state: String,         // LISTEN, ESTABLISHED, TIME_WAIT, etc.
    pub pid: Option<u32>,
    pub process_name: Option<String>,
}

pub fn enumerate_connections() -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    #[cfg(target_os = "linux")]
    {
        use netstat2::{get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, SocketInfo};

        let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
        let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;

        let sockets = get_sockets_info(af_flags, proto_flags)?;
        let mut results = Vec::new();

        for socket in sockets {
            let (protocol, local_addr, local_port, remote_addr, remote_port, state, pid) = match socket.protocol_socket_info {
                ProtocolSocketInfo::Tcp(tcp) => {
                    ("tcp", tcp.local_addr, tcp.local_port, tcp.remote_addr, tcp.remote_port, format!("{:?}", tcp.state), tcp.associated_pids.first().copied())
                }
                ProtocolSocketInfo::Udp(udp) => {
                    ("udp", udp.local_addr, udp.local_port, udp.remote_addr, udp.remote_port, "UNCONNECTED".to_string(), udp.associated_pids.first().copied())
                }
            };

            let conn = NetworkConnection {
                protocol: protocol.to_string(),
                local_address: local_addr,
                local_port,
                remote_address: remote_addr,
                remote_port,
                state,
                pid,
                process_name: pid.and_then(get_process_name),
            };

            results.push(serde_json::to_value(conn)?);
        }

        Ok(results)
    }

    #[cfg(target_os = "windows")]
    {
        // Windows implementation would use GetExtendedTcpTable/GetExtendedUdpTable
        Ok(Vec::new())
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Ok(Vec::new())
    }
}

fn get_process_name(pid: u32) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string(format!("/proc/{}/comm", pid))
            .ok()
            .map(|s| s.trim().to_string())
    }

    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}