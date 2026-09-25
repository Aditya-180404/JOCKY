//! jockey Runtime - System information collection

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    pub hostname: String,
    pub os: String,
    pub os_version: String,
    pub kernel_version: String,
    pub architecture: String,
    pub cpu_count: usize,
    pub total_memory_bytes: u64,
    pub boot_time: Option<chrono::DateTime<chrono::Utc>>,
    pub uptime_seconds: u64,
    pub timezone: String,
    pub locale: String,
    // Extended fields
    pub machine_id: Option<String>,
    pub cpu_model: Option<String>,
    pub cpu_cores: Option<usize>,
    pub cpu_threads: Option<usize>,
    pub cpu_frequency_mhz: Option<u64>,
    pub virtualization: Option<String>,
    pub firmware_vendor: Option<String>,
    pub firmware_version: Option<String>,
    pub firmware_date: Option<String>,
    pub secure_boot: Option<bool>,
    pub disks: Vec<DiskInfo>,
    pub partitions: Vec<PartitionInfo>,
    pub network_interfaces: Vec<NetworkInterface>,
    pub installed_software: Vec<SoftwareInfo>,
    pub packages: Vec<PackageInfo>,
    pub users: Vec<UserInfo>,
    pub groups: Vec<GroupInfo>,
    pub environment_variables: Vec<EnvVar>,
    pub system_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskInfo {
    pub device: String,
    pub model: Option<String>,
    pub serial: Option<String>,
    pub size_bytes: u64,
    pub type_: String, // HDD, SSD, NVMe, etc.
    pub partitions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartitionInfo {
    pub device: String,
    pub mount_point: Option<String>,
    pub filesystem: Option<String>,
    pub size_bytes: u64,
    pub used_bytes: u64,
    pub free_bytes: u64,
    pub label: Option<String>,
    pub uuid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    pub mac_address: Option<String>,
    pub ipv4_addresses: Vec<String>,
    pub ipv6_addresses: Vec<String>,
    pub mtu: Option<u32>,
    pub flags: Vec<String>,
    pub speed_mbps: Option<u64>,
    pub driver: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoftwareInfo {
    pub name: String,
    pub version: Option<String>,
    pub publisher: Option<String>,
    pub install_date: Option<String>,
    pub install_location: Option<String>,
    pub uninstall_string: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageInfo {
    pub name: String,
    pub version: String,
    pub architecture: Option<String>,
    pub description: Option<String>,
    pub install_date: Option<String>,
    pub package_manager: String, // apt, dpkg, rpm, winget, chocolatey, etc.
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub username: String,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub home_dir: Option<String>,
    pub shell: Option<String>,
    pub full_name: Option<String>,
    pub last_login: Option<String>,
    pub password_status: Option<String>, // locked, no password, etc.
    pub groups: Vec<String>,
    pub is_system_account: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupInfo {
    pub name: String,
    pub gid: Option<u32>,
    pub members: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvVar {
    pub name: String,
    pub value: String,
}

impl SystemInfo {
    pub fn collect() -> Result<Self, Box<dyn std::error::Error>> {
        #[cfg(target_os = "linux")]
        {
            use std::fs;

            let hostname = fs::read_to_string("/etc/hostname")?.trim().to_string();
            let os_release = fs::read_to_string("/etc/os-release")?;
            let os = os_release
                .lines()
                .find(|l| l.starts_with("PRETTY_NAME="))
                .map(|l| l.trim_start_matches("PRETTY_NAME=").trim_matches('"'))
                .unwrap_or("Unknown")
                .to_string();
            let os_version = os_release
                .lines()
                .find(|l| l.starts_with("VERSION_ID="))
                .map(|l| l.trim_start_matches("VERSION_ID=").trim_matches('"'))
                .unwrap_or("Unknown")
                .to_string();

            let kernel = fs::read_to_string("/proc/version")?
                .split_whitespace()
                .nth(2)
                .unwrap_or("Unknown")
                .to_string();

            let arch = std::env::consts::ARCH.to_string();

            let cpu_count = std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1);

            let meminfo = fs::read_to_string("/proc/meminfo")?;
            let total_memory_kb = meminfo
                .lines()
                .find(|l| l.starts_with("MemTotal:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);
            let total_memory_bytes = total_memory_kb * 1024;

            let boot_time = fs::read_to_string("/proc/stat")?
                .lines()
                .find(|l| l.starts_with("btime "))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|s| s.parse::<i64>().ok())
                .map(|ts| chrono::DateTime::from_timestamp(ts, 0).unwrap());

            let uptime_str = fs::read_to_string("/proc/uptime")?;
            let uptime_seconds = uptime_str
                .split_whitespace()
                .next()
                .and_then(|s| s.parse::<f64>().ok())
                .unwrap_or(0.0) as u64;

            // Extended fields - Linux
            let machine_id = fs::read_to_string("/etc/machine-id").ok().map(|s| s.trim().to_string());

            let cpu_info = fs::read_to_string("/proc/cpuinfo")?;
            let cpu_model = cpu_info
                .lines()
                .find(|l| l.starts_with("model name"))
                .map(|l| l.split(':').nth(1).unwrap_or("").trim().to_string());
            let cpu_cores = cpu_info
                .lines()
                .filter(|l| l.starts_with("cpu cores"))
                .map(|l| l.split(':').nth(1).unwrap_or("").trim().parse::<usize>().unwrap_or(0))
                .next();
            let cpu_threads = cpu_info
                .lines()
                .filter(|l| l.starts_with("siblings"))
                .map(|l| l.split(':').nth(1).unwrap_or("").trim().parse::<usize>().unwrap_or(0))
                .next();
            let cpu_frequency_mhz = cpu_info
                .lines()
                .find(|l| l.starts_with("cpu MHz"))
                .map(|l| l.split(':').nth(1).unwrap_or("").trim().parse::<u64>().unwrap_or(0));

            let virtualization = detect_virtualization();

            let (firmware_vendor, firmware_version, firmware_date) = read_firmware_info();

            let secure_boot = read_secure_boot();

            let disks = collect_disks();
            let partitions = collect_partitions();
            let network_interfaces = collect_network_interfaces();
            let installed_software = collect_installed_software_linux();
            let packages = collect_packages_linux();
            let (users, groups) = collect_users_and_groups_linux();
            let environment_variables = collect_environment_variables();
            let system_paths = collect_system_paths();

            Ok(SystemInfo {
                hostname,
                os,
                os_version,
                kernel_version: kernel,
                architecture: arch,
                cpu_count,
                total_memory_bytes,
                boot_time,
                uptime_seconds,
                timezone: std::env::var("TZ").unwrap_or_else(|_| "UTC".to_string()),
                locale: std::env::var("LANG").unwrap_or_else(|_| "C".to_string()),
                machine_id,
                cpu_model,
                cpu_cores,
                cpu_threads,
                cpu_frequency_mhz,
                virtualization,
                firmware_vendor,
                firmware_version,
                firmware_date,
                secure_boot,
                disks,
                partitions,
                network_interfaces,
                installed_software,
                packages,
                users,
                groups,
                environment_variables,
                system_paths,
            })
        }

        #[cfg(target_os = "windows")]
        {
            let hostname = std::process::Command::new("cmd")
                .args(["/C", "hostname"])
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|| "windows-host".to_string());

            let os_version = std::process::Command::new("cmd")
                .args(["/C", "ver"])
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|| "Windows".to_string());

            let architecture = std::env::consts::ARCH.to_string();
            let mem_output = std::process::Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-Command",
                    "(Get-CimInstance Win32_OperatingSystem).TotalVisibleMemorySize",
                ])
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .and_then(|s| s.trim().parse::<u64>().ok());
            let total_memory_bytes = mem_output.map(|kb| kb * 1024).unwrap_or(0);

            let uptime_seconds = std::process::Command::new("powershell")
                .args(["-NoProfile", "-Command", "[int]([DateTime]::UtcNow - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime()).TotalSeconds"])
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .and_then(|s| s.trim().parse::<u64>().ok())
                .unwrap_or(0);

            // Extended fields - Windows
            let machine_id = get_machine_guid();
            let (cpu_model, cpu_cores, cpu_threads, cpu_frequency_mhz) = get_cpu_info_windows();
            let virtualization = detect_virtualization_windows();
            let (firmware_vendor, firmware_version, firmware_date) = get_firmware_info_windows();
            let secure_boot = get_secure_boot_windows();
            let disks = collect_disks_windows();
            let partitions = collect_partitions_windows();
            let network_interfaces = collect_network_interfaces_windows();
            let installed_software = collect_installed_software_windows();
            let packages = collect_packages_windows();
            let (users, groups) = collect_users_and_groups_windows();
            let environment_variables = collect_environment_variables_windows();
            let system_paths = collect_system_paths_windows();

            Ok(SystemInfo {
                hostname,
                os: "Windows".to_string(),
                os_version,
                kernel_version: "NT".to_string(),
                architecture,
                cpu_count: std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(1),
                total_memory_bytes,
                boot_time: None,
                uptime_seconds,
                timezone: "UTC".to_string(),
                locale: "en-US".to_string(),
                machine_id,
                cpu_model,
                cpu_cores,
                cpu_threads,
                cpu_frequency_mhz,
                virtualization,
                firmware_vendor,
                firmware_version,
                firmware_date,
                secure_boot,
                disks,
                partitions,
                network_interfaces,
                installed_software,
                packages,
                users,
                groups,
                environment_variables,
                system_paths,
            })
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            Ok(SystemInfo {
                hostname: "unknown".to_string(),
                os: "Unknown".to_string(),
                os_version: "Unknown".to_string(),
                kernel_version: "Unknown".to_string(),
                architecture: std::env::consts::ARCH.to_string(),
                cpu_count: std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(1),
                total_memory_bytes: 0,
                boot_time: None,
                uptime_seconds: 0,
                timezone: "UTC".to_string(),
                locale: "C".to_string(),
                machine_id: None,
                cpu_model: None,
                cpu_cores: None,
                cpu_threads: None,
                cpu_frequency_mhz: None,
                virtualization: None,
                firmware_vendor: None,
                firmware_version: None,
                firmware_date: None,
                secure_boot: None,
                disks: Vec::new(),
                partitions: Vec::new(),
                network_interfaces: Vec::new(),
                installed_software: Vec::new(),
                packages: Vec::new(),
                users: Vec::new(),
                groups: Vec::new(),
                environment_variables: Vec::new(),
                system_paths: Vec::new(),
            })
        }
    }
}

// Linux helper functions
#[cfg(target_os = "linux")]
fn detect_virtualization() -> Option<String> {
    use std::fs;
    // Check for common virtualization indicators
    if fs::read_to_string("/proc/cpuinfo").unwrap_or_default().contains("hypervisor") {
        return Some("hypervisor".to_string());
    }
    if fs::metadata("/.dockerenv").is_ok() {
        return Some("docker".to_string());
    }
    if let Ok(content) = fs::read_to_string("/sys/class/dmi/id/product_name") {
        let content = content.to_lowercase();
        if content.contains("vmware") || content.contains("virtualbox") || content.contains("qemu") || content.contains("kvm") || content.contains("xen") {
            return Some(content.trim().to_string());
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn read_firmware_info() -> (Option<String>, Option<String>, Option<String>) {
    use std::fs;
    let vendor = fs::read_to_string("/sys/class/dmi/id/bios_vendor").ok().map(|s| s.trim().to_string());
    let version = fs::read_to_string("/sys/class/dmi/id/bios_version").ok().map(|s| s.trim().to_string());
    let date = fs::read_to_string("/sys/class/dmi/id/bios_date").ok().map(|s| s.trim().to_string());
    (vendor, version, date)
}

#[cfg(target_os = "linux")]
fn read_secure_boot() -> Option<bool> {
    use std::fs;
    // Check UEFI secure boot status via mokutil or /sys/firmware/efi
    fs::read_to_string("/sys/firmware/efi/secureboot").ok().and_then(|s| s.trim().parse::<u8>().ok()).map(|v| v == 1)
}

#[cfg(target_os = "linux")]
fn collect_disks() -> Vec<DiskInfo> {
    use std::fs;
    let mut disks = Vec::new();

    if let Ok(block_devices) = fs::read_dir("/sys/block") {
        for entry in block_devices.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            // Skip loop, ram, and virtual devices
            if name.starts_with("loop") || name.starts_with("ram") || name.starts_with("dm-") || name.starts_with("md") {
                continue;
            }

            let device_path = format!("/dev/{}", name);
            let model = fs::read_to_string(format!("/sys/block/{}/device/model", name)).ok().map(|s| s.trim().to_string());
            let serial = fs::read_to_string(format!("/sys/block/{}/device/serial", name)).ok().map(|s| s.trim().to_string());
            let size_bytes = fs::read_to_string(format!("/sys/block/{}/size", name))
                .ok()
                .and_then(|s| s.trim().parse::<u64>().ok())
                .map(|sectors| sectors * 512)
                .unwrap_or(0);

            let type_ = fs::read_to_string(format!("/sys/block/{}/queue/rotational", name))
                .ok()
                .and_then(|s| s.trim().parse::<u8>().ok())
                .map(|r| if r == 0 { "SSD/NVMe".to_string() } else { "HDD".to_string() })
                .unwrap_or_else(|| "Unknown".to_string());

            let mut partitions = Vec::new();
            if let Ok(part_dir) = fs::read_dir(format!("/sys/block/{}/", name)) {
                for part in part_dir.flatten() {
                    let part_name = part.file_name().to_string_lossy().to_string();
                    if part_name.starts_with(&name) && part_name != name {
                        partitions.push(format!("/dev/{}", part_name));
                    }
                }
            }

            disks.push(DiskInfo {
                device: device_path,
                model,
                serial,
                size_bytes,
                type_,
                partitions,
            });
        }
    }
    disks
}

#[cfg(target_os = "linux")]
fn collect_partitions() -> Vec<PartitionInfo> {
    use std::fs;
    let mut partitions = Vec::new();

    if let Ok(mounts) = fs::read_to_string("/proc/mounts") {
        for line in mounts.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 3 {
                continue;
            }
            let device = parts[0].to_string();
            let mount_point = parts[1].to_string();
            let filesystem = parts[2].to_string();

            // Skip virtual filesystems
            if filesystem == "proc" || filesystem == "sysfs" || filesystem == "devtmpfs" || filesystem == "tmpfs" || filesystem == "devpts" || filesystem == "cgroup" || filesystem == "cgroup2" || filesystem == "pstore" || filesystem == "efivarfs" || filesystem == "mqueue" || filesystem == "hugetlbfs" || filesystem == "configfs" || filesystem == "autofs" || filesystem == "fuse.gvfsd-fuse" || filesystem == "fusectl" || filesystem == "tracefs" {
                continue;
            }

            let (size_bytes, used_bytes, free_bytes) = if fs::metadata(&mount_point).is_ok() {
                // This is a rough approximation - use statvfs for real values.
                (0, 0, 0)
            } else {
                (0, 0, 0)
            };

            partitions.push(PartitionInfo {
                device,
                mount_point: Some(mount_point),
                filesystem: Some(filesystem),
                size_bytes,
                used_bytes,
                free_bytes,
                label: None,
                uuid: None,
            });
        }
    }
    partitions
}

#[cfg(target_os = "linux")]
fn collect_network_interfaces() -> Vec<NetworkInterface> {
    use std::fs;
    let mut interfaces = Vec::new();

    if let Ok(net_dir) = fs::read_dir("/sys/class/net") {
        for entry in net_dir.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name == "lo" { continue; }

            let mac_address = fs::read_to_string(format!("/sys/class/net/{}/address", name)).ok().map(|s| s.trim().to_string());
            let mtu = fs::read_to_string(format!("/sys/class/net/{}/mtu", name)).ok().and_then(|s| s.trim().parse::<u32>().ok());
            let flags = fs::read_to_string(format!("/sys/class/net/{}/flags", name)).ok().map(|s| s.trim().to_string());
            let speed_mbps = fs::read_to_string(format!("/sys/class/net/{}/speed", name)).ok().and_then(|s| s.trim().parse::<u64>().ok());
            let driver = fs::read_to_string(format!("/sys/class/net/{}/device/driver/module/name", name)).ok().map(|s| s.trim().to_string());

            // Get IP addresses from ip command or /proc/net/if_inet6
            let (ipv4_addresses, ipv6_addresses) = get_interface_ips(&name);

            interfaces.push(NetworkInterface {
                name,
                mac_address,
                ipv4_addresses,
                ipv6_addresses,
                mtu,
                flags: flags.map(|f| vec![f]).unwrap_or_default(),
                speed_mbps,
                driver,
            });
        }
    }
    interfaces
}

#[cfg(target_os = "linux")]
fn get_interface_ips(interface: &str) -> (Vec<String>, Vec<String>) {
    use std::process::Command;
    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();

    if let Ok(output) = Command::new("ip").args(["-4", "addr", "show", "dev", interface]).output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if line.contains("inet ") {
                if let Some(addr) = line.split_whitespace().nth(1) {
                    ipv4.push(addr.to_string());
                }
            }
        }
    }

    if let Ok(output) = Command::new("ip").args(["-6", "addr", "show", "dev", interface]).output() {
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

#[cfg(target_os = "linux")]
fn collect_installed_software_linux() -> Vec<SoftwareInfo> {
    // On Linux, software is typically managed via package managers
    // This returns empty for now - packages are in collect_packages
    Vec::new()
}

#[cfg(target_os = "linux")]
fn collect_packages_linux() -> Vec<PackageInfo> {
    use std::process::Command;
    let mut packages = Vec::new();

    // Try dpkg (Debian/Ubuntu)
    if let Ok(output) = Command::new("dpkg-query").args(["-W", "-f=${Package}\t${Version}\t${Architecture}\t${Description}\n"]).output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() >= 2 {
                packages.push(PackageInfo {
                    name: parts[0].to_string(),
                    version: parts[1].to_string(),
                    architecture: parts.get(2).map(|s| s.to_string()),
                    description: parts.get(3).map(|s| s.to_string()),
                    install_date: None,
                    package_manager: "dpkg".to_string(),
                });
            }
        }
        if !packages.is_empty() {
            return packages;
        }
    }

    // Try rpm (RHEL/Fedora)
    if let Ok(output) = Command::new("rpm").args(["-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{SUMMARY}\n"]).output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() >= 2 {
                packages.push(PackageInfo {
                    name: parts[0].to_string(),
                    version: parts[1].to_string(),
                    architecture: parts.get(2).map(|s| s.to_string()),
                    description: parts.get(3).map(|s| s.to_string()),
                    install_date: None,
                    package_manager: "rpm".to_string(),
                });
            }
        }
        if !packages.is_empty() {
            return packages;
        }
    }

    packages
}

#[cfg(target_os = "linux")]
fn collect_users_and_groups_linux() -> (Vec<UserInfo>, Vec<GroupInfo>) {
    use std::fs;
    let mut users = Vec::new();
    let mut groups = Vec::new();

    // Read /etc/passwd for users
    if let Ok(passwd) = fs::read_to_string("/etc/passwd") {
        for line in passwd.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 7 {
                let uid = parts[2].parse::<u32>().unwrap_or(0);
                let is_system = uid < 1000 && uid != 0;

                users.push(UserInfo {
                    username: parts[0].to_string(),
                    uid: Some(uid),
                    gid: parts[3].parse::<u32>().ok(),
                    home_dir: Some(parts[5].to_string()),
                    shell: Some(parts[6].to_string()),
                    full_name: Some(parts[4].to_string()),
                    last_login: None, // Would need lastlog or similar
                    password_status: None, // Would need /etc/shadow
                    groups: Vec::new(), // Will be populated from groups
                    is_system_account: is_system,
                });
            }
        }
    }

    // Read /etc/group for groups
    if let Ok(group_file) = fs::read_to_string("/etc/group") {
        for line in group_file.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 4 {
                let members: Vec<String> = parts[3].split(',').map(|s| s.to_string()).collect();
                let gid = parts[2].parse::<u32>().ok();

                groups.push(GroupInfo {
                    name: parts[0].to_string(),
                    gid,
                    members: members.clone(),
                });

                // Add group membership to users
                for member in members {
                    if let Some(user) = users.iter_mut().find(|u| u.username == member) {
                        user.groups.push(parts[0].to_string());
                    }
                }
            }
        }
    }

    (users, groups)
}

#[cfg(target_os = "linux")]
fn collect_environment_variables() -> Vec<EnvVar> {
    std::env::vars()
        .map(|(name, value)| EnvVar { name, value })
        .collect()
}

#[cfg(target_os = "linux")]
fn collect_system_paths() -> Vec<String> {
    vec![
        "/bin".to_string(),
        "/sbin".to_string(),
        "/usr/bin".to_string(),
        "/usr/sbin".to_string(),
        "/usr/local/bin".to_string(),
        "/usr/local/sbin".to_string(),
        "/opt".to_string(),
        "/etc".to_string(),
        "/var".to_string(),
        "/tmp".to_string(),
        "/home".to_string(),
        "/root".to_string(),
        "/lib".to_string(),
        "/lib64".to_string(),
        "/usr/lib".to_string(),
        "/usr/lib64".to_string(),
    ]
}

// Windows helper functions
#[cfg(target_os = "windows")]
fn get_machine_guid() -> Option<String> {
    use winreg::enums::*;
    use winreg::RegKey;
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(key) = hklm.open_subkey(r"SOFTWARE\Microsoft\Cryptography") {
        key.get_value("MachineGuid").ok()
    } else {
        None
    }
}

#[cfg(target_os = "windows")]
fn get_cpu_info_windows() -> (Option<String>, Option<usize>, Option<usize>, Option<u64>) {
    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", "Get-CimInstance Win32_Processor | Select-Object Name,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed | ConvertTo-Json -Compress"])
        .output();

    if let Ok(output) = output {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&stdout) {
            let items: Vec<serde_json::Value> = match val {
                serde_json::Value::Array(arr) => arr,
                serde_json::Value::Object(_) => vec![val],
                _ => vec![],
            };
            if let Some(first) = items.first() {
                let name = first.get("Name").and_then(|v| v.as_str()).map(|s| s.to_string());
                let cores = first.get("NumberOfCores").and_then(|v| v.as_u64()).map(|v| v as usize);
                let threads = first.get("NumberOfLogicalProcessors").and_then(|v| v.as_u64()).map(|v| v as usize);
                let freq = first.get("MaxClockSpeed").and_then(|v| v.as_u64());
                return (name, cores, threads, freq);
            }
        }
    }
    (None, None, None, None)
}

#[cfg(target_os = "windows")]
fn detect_virtualization_windows() -> Option<String> {
    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", "(Get-CimInstance Win32_ComputerSystem).Manufacturer"])
        .output();

    if let Ok(output) = output {
        let stdout = String::from_utf8_lossy(&output.stdout).to_lowercase();
        if stdout.contains("vmware") { return Some("VMware".to_string()); }
        if stdout.contains("virtualbox") { return Some("VirtualBox".to_string()); }
        if stdout.contains("qemu") { return Some("QEMU/KVM".to_string()); }
        if stdout.contains("xen") { return Some("Xen".to_string()); }
        if stdout.contains("microsoft corporation") && stdout.contains("virtual machine") { return Some("Hyper-V".to_string()); }
    }
    None
}

#[cfg(target_os = "windows")]
fn get_firmware_info_windows() -> (Option<String>, Option<String>, Option<String>) {
    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", "Get-CimInstance Win32_BIOS | Select-Object Manufacturer,SMBIOSBIOSVersion,ReleaseDate | ConvertTo-Json -Compress"])
        .output();

    if let Ok(output) = output {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&stdout) {
            let items: Vec<serde_json::Value> = match val {
                serde_json::Value::Array(arr) => arr,
                serde_json::Value::Object(_) => vec![val],
                _ => vec![],
            };
            if let Some(first) = items.first() {
                let vendor = first.get("Manufacturer").and_then(|v| v.as_str()).map(|s| s.to_string());
                let version = first.get("SMBIOSBIOSVersion").and_then(|v| v.as_str()).map(|s| s.to_string());
                let date = first.get("ReleaseDate").and_then(|v| v.as_str()).map(|s| s.to_string());
                return (vendor, version, date);
            }
        }
    }
    (None, None, None)
}

#[cfg(target_os = "windows")]
fn get_secure_boot_windows() -> Option<bool> {
    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", "Confirm-SecureBootUEFI"])
        .output();

    if let Ok(output) = output {
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_lowercase();
        return Some(stdout == "true");
    }
    None
}

#[cfg(target_os = "windows")]
fn collect_disks_windows() -> Vec<DiskInfo> {
    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", "Get-CimInstance Win32_DiskDrive | Select-Object DeviceID,Model,SerialNumber,Size,MediaType | ConvertTo-Json -Compress"])
        .output();

    let mut disks = Vec::new();
    if let Ok(output) = output {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&stdout) {
            let items: Vec<serde_json::Value> = match val {
                serde_json::Value::Array(arr) => arr,
                serde_json::Value::Object(_) => vec![val],
                _ => vec![],
            };
            for item in items {
                disks.push(DiskInfo {
                    device: item.get("DeviceID").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    model: item.get("Model").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    serial: item.get("SerialNumber").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    size_bytes: item.get("Size").and_then(|v| v.as_u64()).unwrap_or(0),
                    type_: item.get("MediaType").and_then(|v| v.as_str()).unwrap_or("Unknown").to_string(),
                    partitions: Vec::new(), // Could be populated separately
                });
            }
        }
    }
    disks
}

#[cfg(target_os = "windows")]
fn collect_partitions_windows() -> Vec<PartitionInfo> {
    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", "Get-CimInstance Win32_LogicalDisk | Select-Object DeviceID,FileSystem,Size,FreeSpace,VolumeName,VolumeSerialNumber | ConvertTo-Json -Compress"])
        .output();

    let mut partitions = Vec::new();
    if let Ok(output) = output {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&stdout) {
            let items: Vec<serde_json::Value> = match val {
                serde_json::Value::Array(arr) => arr,
                serde_json::Value::Object(_) => vec![val],
                _ => vec![],
            };
            for item in items {
                let size = item.get("Size").and_then(|v| v.as_u64()).unwrap_or(0);
                let free = item.get("FreeSpace").and_then(|v| v.as_u64()).unwrap_or(0);
                partitions.push(PartitionInfo {
                    device: item.get("DeviceID").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    mount_point: None,
                    filesystem: item.get("FileSystem").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    size_bytes: size,
                    used_bytes: size.saturating_sub(free),
                    free_bytes: free,
                    label: item.get("VolumeName").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    uuid: item.get("VolumeSerialNumber").and_then(|v| v.as_str()).map(|s| s.to_string()),
                });
            }
        }
    }
    partitions
}

#[cfg(target_os = "windows")]
fn collect_network_interfaces_windows() -> Vec<NetworkInterface> {
    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", "Get-NetAdapter | Where-Object {$_.Status -ne 'Disconnected'} | Select-Object Name,MacAddress,InterfaceDescription,LinkSpeed | ConvertTo-Json -Compress"])
        .output();

    let mut interfaces = Vec::new();
    if let Ok(output) = output {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&stdout) {
            let items: Vec<serde_json::Value> = match val {
                serde_json::Value::Array(arr) => arr,
                serde_json::Value::Object(_) => vec![val],
                _ => vec![],
            };
            for item in items {
                interfaces.push(NetworkInterface {
                    name: item.get("Name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    mac_address: item.get("MacAddress").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    ipv4_addresses: Vec::new(), // Would need separate query
                    ipv6_addresses: Vec::new(),
                    mtu: None,
                    flags: Vec::new(),
                    speed_mbps: item.get("LinkSpeed").and_then(|v| v.as_u64()).map(|s| s / 1_000_000),
                    driver: item.get("InterfaceDescription").and_then(|v| v.as_str()).map(|s| s.to_string()),
                });
            }
        }
    }
    interfaces
}

#[cfg(target_os = "windows")]
fn collect_installed_software_windows() -> Vec<SoftwareInfo> {
    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Where-Object {$_.DisplayName} | Select-Object DisplayName,DisplayVersion,Publisher,InstallDate,InstallLocation,UninstallString | ConvertTo-Json -Compress"])
        .output();

    let mut software = Vec::new();
    if let Ok(output) = output {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&stdout) {
            let items: Vec<serde_json::Value> = match val {
                serde_json::Value::Array(arr) => arr,
                serde_json::Value::Object(_) => vec![val],
                _ => vec![],
            };
            for item in items {
                software.push(SoftwareInfo {
                    name: item.get("DisplayName").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    version: item.get("DisplayVersion").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    publisher: item.get("Publisher").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    install_date: item.get("InstallDate").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    install_location: item.get("InstallLocation").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    uninstall_string: item.get("UninstallString").and_then(|v| v.as_str()).map(|s| s.to_string()),
                });
            }
        }
    }
    software
}

#[cfg(target_os = "windows")]
fn collect_packages_windows() -> Vec<PackageInfo> {
    // Could query winget, chocolatey, scoop
    Vec::new()
}

#[cfg(target_os = "windows")]
fn collect_users_and_groups_windows() -> (Vec<UserInfo>, Vec<GroupInfo>) {
    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", "Get-LocalUser | Select-Object Name,SID,Description,Enabled,LastLogon,PasswordExpires,UserMayChangePassword,PasswordRequired | ConvertTo-Json -Compress"])
        .output();

    let mut users = Vec::new();
    if let Ok(output) = output {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&stdout) {
            let items: Vec<serde_json::Value> = match val {
                serde_json::Value::Array(arr) => arr,
                serde_json::Value::Object(_) => vec![val],
                _ => vec![],
            };
            for item in items {
                users.push(UserInfo {
                    username: item.get("Name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    uid: None,
                    gid: None,
                    home_dir: None,
                    shell: None,
                    full_name: item.get("Description").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    last_login: item.get("LastLogon").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    password_status: if item.get("PasswordRequired").and_then(|v| v.as_bool()).unwrap_or(true) { Some("required".to_string()) } else { Some("none".to_string()) },
                    groups: Vec::new(),
                    is_system_account: false,
                });
            }
        }
    }

    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", "Get-LocalGroup | Select-Object Name,SID,Description | ConvertTo-Json -Compress"])
        .output();

    let mut groups = Vec::new();
    if let Ok(output) = output {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&stdout) {
            let items: Vec<serde_json::Value> = match val {
                serde_json::Value::Array(arr) => arr,
                serde_json::Value::Object(_) => vec![val],
                _ => vec![],
            };
            for item in items {
                groups.push(GroupInfo {
                    name: item.get("Name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    gid: None,
                    members: Vec::new(),
                });
            }
        }
    }

    (users, groups)
}

#[cfg(target_os = "windows")]
fn collect_environment_variables_windows() -> Vec<EnvVar> {
    std::env::vars()
        .map(|(name, value)| EnvVar { name, value })
        .collect()
}

#[cfg(target_os = "windows")]
fn collect_system_paths_windows() -> Vec<String> {
    vec![
        r"C:\Windows".to_string(),
        r"C:\Windows\System32".to_string(),
        r"C:\Windows\SysWOW64".to_string(),
        r"C:\Program Files".to_string(),
        r"C:\Program Files (x86)".to_string(),
        r"C:\ProgramData".to_string(),
        r"C:\Users".to_string(),
        r"C:\Temp".to_string(),
        r"C:\Windows\Temp".to_string(),
    ]
}

pub fn collect_system_info() -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let info = SystemInfo::collect()?;
    Ok(serde_json::to_value(info)?)
}

// Collector function for detailed system info (matches capability registry)
pub fn collect_system_info_detailed() -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    // Same as collect_system_info for now - the detailed info is in SystemInfo
    collect_system_info()
}
