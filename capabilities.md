# JOCKEY Capability Inventory

**Total Capabilities:** 247 | **Implemented:** 240 | **Partial:** 1 | **Requires Elevation:** 4 | **Platform Restricted:** 1 | **Unsupported:** 1 | **Coverage:** 97.2%

| ID | Name | Category | Platforms | Privilege | Status | MITRE ATT&CK | Implemented |
|:---|:---|:---|:---|:---|:---|:---|:---:|
| app.browser | Browser Artifacts | ApplicationArtifact | Both | User | IMPLEMENTED | T1555 | ✓ |
| app.browser.cookies | Browser Cookies | ApplicationArtifact | Both | User | IMPLEMENTED | T1555 | ✓ |
| app.browser.downloads | Browser Downloads | ApplicationArtifact | Both | User | IMPLEMENTED | T1555 | ✓ |
| app.browser.extensions | Browser Extensions | ApplicationArtifact | Both | User | IMPLEMENTED | T1555 | ✓ |
| app.browser.history | Browser History | ApplicationArtifact | Both | User | IMPLEMENTED | T1555 | ✓ |
| app.browser.inventory | Browser Inventory | ApplicationArtifact | Both | User | IMPLEMENTED | T1555 | ✓ |
| app.email | Email Client Artifacts | ApplicationArtifact | Both | User | IMPLEMENTED | T1114 | ✓ |
| app.office | Office Artifacts | ApplicationArtifact | Both | User | IMPLEMENTED | T1137 | ✓ |
| artifact.amcache | Amcache.hve | WindowsArtifact | Windows | Admin | REQUIRES_ELEVATION | T1057 | ✓ |
| artifact.auditd | Auditd Inventory | LinuxArtifact | Linux | User | IMPLEMENTED | T1562 | ✓ |
| artifact.auth.logs | Auth Logs | LinuxArtifact | Linux | User | IMPLEMENTED | T1110 | ✓ |
| artifact.bash.history | Bash History | LinuxArtifact | Linux | User | IMPLEMENTED | T1552 | ✓ |
| artifact.container | Container Artifacts | LinuxArtifact | Linux | User | IMPLEMENTED | T1610 | ✓ |
| artifact.cron | Cron Jobs | LinuxArtifact | Linux | User | IMPLEMENTED | T1053 | ✓ |
| artifact.etw | ETW Logs | WindowsArtifact | Windows | Admin | REQUIRES_ELEVATION | T1562 | ✓ |
| artifact.event.logs | Event Logs | WindowsArtifact | Windows | Admin | IMPLEMENTED | T1562 | ✓ |
| artifact.journal | Journal Inventory | LinuxArtifact | Linux | User | IMPLEMENTED | T1562 | ✓ |
| artifact.jump.lists | Jump Lists | WindowsArtifact | Windows | User | IMPLEMENTED | T1057 | ✓ |
| artifact.jumplists | Jump Lists | WindowsArtifact | Windows | User | IMPLEMENTED | T1057 | ✓ |
| artifact.lnk | LNK Shortcut Files | WindowsArtifact | Windows | User | IMPLEMENTED | T1057 | ✓ |
| artifact.login.config | Login Configuration | LinuxArtifact | Linux | User | IMPLEMENTED | T1078 | ✓ |
| artifact.prefetch | Prefetch Files | WindowsArtifact | Windows | User | IMPLEMENTED | T1057 | ✓ |
| artifact.recent.files | Recent Files | WindowsArtifact | Windows | User | IMPLEMENTED | T1070 | ✓ |
| artifact.recycle.bin | Recycle Bin Inventory | WindowsArtifact | Windows | User | IMPLEMENTED | T1070 | ✓ |
| artifact.recycle_bin | Recycle Bin | WindowsArtifact | Windows | User | IMPLEMENTED | T1070 | ✓ |
| artifact.shell.history | Shell History | LinuxArtifact | Linux | User | IMPLEMENTED | T1552 | ✓ |
| artifact.shell_history | Shell History | LinuxArtifact | Linux | User | IMPLEMENTED | T1552 | ✓ |
| artifact.shellbags | Shellbags | WindowsArtifact | Windows | User | IMPLEMENTED | T1083 | ✓ |
| artifact.srum | SRUM Database | WindowsArtifact | Windows | Admin | REQUIRES_ELEVATION | T1057 | ✓ |
| artifact.ssh | SSH Artifacts | LinuxArtifact | Linux | User | IMPLEMENTED | T1552 | ✓ |
| artifact.ssh_config | SSH Configuration | LinuxArtifact | Linux | User | IMPLEMENTED | T1552 | ✓ |
| artifact.sudo | Sudo Logs | LinuxArtifact | Linux | User | IMPLEMENTED | T1548 | ✓ |
| artifact.systemd | Systemd Units | LinuxArtifact | Linux | User | IMPLEMENTED | T1543 | ✓ |
| artifact.zsh.history | Zsh History | LinuxArtifact | Linux | User | IMPLEMENTED | T1552 | ✓ |
| auth.credential_artifacts | Credential Artifacts | Authentication | Both | Admin | IMPLEMENTED | T1003, T1555 | ✓ |
| auth.failed.logins | Failed Logins | Authentication | Both | Admin | IMPLEMENTED | T1110 | ✓ |
| auth.logon.events | Logon Events | Authentication | Both | Admin | IMPLEMENTED | T1110 | ✓ |
| auth.logon_events | Logon Events | Authentication | Both | Admin | IMPLEMENTED | T1003, T1110 | ✓ |
| auth.pam | PAM Configuration | Authentication | Linux | User | IMPLEMENTED | T1556 | ✓ |
| auth.password.policy | Password Policy | Authentication | Both | User | IMPLEMENTED | T1204 | ✓ |
| auth.policy | Authentication Policy | Authentication | Both | User | IMPLEMENTED | T1210 | ✓ |
| auth.remote.sessions | Remote Sessions | Authentication | Both | User | IMPLEMENTED | T1021 | ✓ |
| auth.ssh.authorized.keys | Authorized Keys | Authentication | Linux | User | IMPLEMENTED | T1552 | ✓ |
| auth.ssh.config | SSH Configuration | Authentication | Linux | User | IMPLEMENTED | T1552 | ✓ |
| auth.ssh.known.hosts | Known Hosts | Authentication | Linux | User | IMPLEMENTED | T1552 | ✓ |
| auth.successful.logins | Successful Logins | Authentication | Both | Admin | IMPLEMENTED | T1110 | ✓ |
| auth.sudoers | Sudoers | Authentication | Linux | User | IMPLEMENTED | T1548 | ✓ |
| auth.windows.logon | Windows Logons | Authentication | Windows | Admin | IMPLEMENTED | T1110 | ✓ |
| backdoor.binary_anomalies | Binary Anomalies | BackdoorRootkit | Both | User | IMPLEMENTED | T1027, T1036 | ✓ |
| backdoor.rootkit_indicators | Rootkit Indicators | BackdoorRootkit | Both | Kernel | PARTIAL | T1014 | ✓ |
| evidence.blockchain_anchor | Blockchain Anchoring | EvidenceIntegrity | Both | User | UNSUPPORTED | — | ✗ |
| evidence.chain_of_custody | Chain of Custody | EvidenceIntegrity | Both | User | IMPLEMENTED | — | ✓ |
| evidence.collector.status | Collector Status | EvidenceIntegrity | Both | User | IMPLEMENTED | — | ✓ |
| evidence.merkle | Merkle Tree Construction | EvidenceIntegrity | Both | User | IMPLEMENTED | — | ✓ |
| evidence.origin | Evidence Origin | EvidenceIntegrity | Both | User | IMPLEMENTED | — | ✓ |
| evidence.provenance | Provenance Metadata | EvidenceIntegrity | Both | User | IMPLEMENTED | — | ✓ |
| evidence.sha256 | SHA-256 Hashing | EvidenceIntegrity | Both | User | IMPLEMENTED | — | ✓ |
| file.code_signature | Code Signature Verification | FileBinaryMetadata | Both | User | IMPLEMENTED | T1553 | ✓ |
| file.elf.metadata | ELF Metadata | FileBinaryMetadata | Linux | User | IMPLEMENTED | T1027 | ✓ |
| file.elf_metadata | ELF Metadata | FileBinaryMetadata | Linux | User | PLATFORM_SPECIFIC | T1027 | ✗ |
| file.entropy | File Entropy Analysis | FileBinaryMetadata | Both | User | IMPLEMENTED | T1027 | ✓ |
| file.hash.sha256 | PE/ELF SHA-256 | FileBinaryMetadata | Both | User | IMPLEMENTED | T1027 | ✓ |
| file.pe.metadata | PE Metadata | FileBinaryMetadata | Windows | User | IMPLEMENTED | T1027 | ✓ |
| file.pe_metadata | PE Metadata | FileBinaryMetadata | Windows | User | IMPLEMENTED | T1027 | ✓ |
| file.signature | Signature Metadata | FileBinaryMetadata | Both | User | IMPLEMENTED | T1553 | ✓ |
| filesystem.alternate.data.streams | ADS Metadata | Filesystem | Windows | User | IMPLEMENTED | T1564 | ✓ |
| filesystem.alternate_data_streams | Alternate Data Streams | Filesystem | Windows | User | IMPLEMENTED | T1564 | ✓ |
| filesystem.deleted.open | Deleted-But-Open Files | Filesystem | Linux | User | IMPLEMENTED | T1083 | ✓ |
| filesystem.enumerate | Filesystem Enumeration | Filesystem | Both | User | IMPLEMENTED | T1083 | ✓ |
| filesystem.executable | Executable Detection | Filesystem | Both | User | IMPLEMENTED | T1036 | ✓ |
| filesystem.hash.md5 | MD5 Hashes | Filesystem | Both | User | IMPLEMENTED | T1027 | ✓ |
| filesystem.hash.sha1 | SHA-1 Hashes | Filesystem | Both | User | IMPLEMENTED | T1027 | ✓ |
| filesystem.hash.sha256 | SHA-256 Hashes | Filesystem | Both | User | IMPLEMENTED | T1027 | ✓ |
| filesystem.hidden | Hidden Files | Filesystem | Both | User | IMPLEMENTED | T1083 | ✓ |
| filesystem.links | Symlinks | Filesystem | Both | User | IMPLEMENTED | T1083 | ✓ |
| filesystem.mounts | Mount Points | Filesystem | Both | User | IMPLEMENTED | T1083 | ✓ |
| filesystem.owner | Ownership | Filesystem | Both | User | IMPLEMENTED | T1083 | ✓ |
| filesystem.path | File Paths | Filesystem | Both | User | IMPLEMENTED | T1083 | ✓ |
| filesystem.permissions | Permissions | Filesystem | Both | User | IMPLEMENTED | T1083 | ✓ |
| filesystem.recent | Recent Files | Filesystem | Both | User | IMPLEMENTED | T1083 | ✓ |
| filesystem.size | File Sizes | Filesystem | Both | User | IMPLEMENTED | T1083 | ✓ |
| filesystem.timestamps | File Timestamps | Filesystem | Both | User | IMPLEMENTED | T1083 | ✓ |
| filesystem.type | File Type | Filesystem | Both | User | IMPLEMENTED | T1083 | ✓ |
| kernel.boot_config | Boot Configuration | KernelDriver | Both | User | IMPLEMENTED | T1542 | ✓ |
| kernel.module.hashes | Kernel Hashes | KernelDriver | Both | User | IMPLEMENTED | T1014 | ✓ |
| kernel.module.params | Module Parameters | KernelDriver | Both | User | IMPLEMENTED | T1014 | ✓ |
| kernel.module.paths | Module Paths | KernelDriver | Both | User | IMPLEMENTED | T1014 | ✓ |
| kernel.module.signatures | Module Signatures | KernelDriver | Both | User | IMPLEMENTED | T1014 | ✓ |
| kernel.module.version | Module Versions | KernelDriver | Both | User | IMPLEMENTED | T1014 | ✓ |
| kernel.modules | Kernel Modules | KernelDriver | Both | User | IMPLEMENTED | T1014 | ✓ |
| kernel.syscalls | System Call Table | KernelDriver | Linux | Kernel | REQUIRES_ELEVATION | T1014 | ✓ |
| network.arp | ARP Table | Network | Both | User | IMPLEMENTED | T1016 | ✓ |
| network.arp_table | ARP/Neighbor Table | Network | Both | User | IMPLEMENTED | T1016 | ✓ |
| network.connections | Network Connections | Network | Both | User | IMPLEMENTED | T1049 | ✓ |
| network.connections.active | Active Connections | Network | Both | User | IMPLEMENTED | T1049 | ✓ |
| network.dns.cache | DNS Cache | Network | Both | User | IMPLEMENTED | T1016 | ✓ |
| network.dns.servers | DNS Servers | Network | Both | User | IMPLEMENTED | T1016 | ✓ |
| network.dns_cache | DNS Cache | Network | Both | Admin | IMPLEMENTED | T1016 | ✓ |
| network.firewall | Firewall Rules | Network | Both | Admin | IMPLEMENTED | T1562 | ✓ |
| network.firewall.policy | Firewall Policy | Network | Both | Admin | IMPLEMENTED | T1562 | ✓ |
| network.hosts | Hosts File | Network | Both | User | IMPLEMENTED | T1016 | ✓ |
| network.interface.addresses | Interface Addresses | Network | Both | User | IMPLEMENTED | T1016 | ✓ |
| network.interfaces | Interface Inventory | Network | Both | User | IMPLEMENTED | T1016 | ✓ |
| network.listeners | Suspicious Listeners | Network | Both | User | IMPLEMENTED | T1049 | ✓ |
| network.listening.ports | Listening Ports | Network | Both | User | IMPLEMENTED | T1049 | ✓ |
| network.listening_ports | Listening Ports | Network | Both | User | IMPLEMENTED | T1049 | ✓ |
| network.mac | MAC Addresses | Network | Both | User | IMPLEMENTED | T1016 | ✓ |
| network.process.relationships | Process Relationships | Network | Both | User | IMPLEMENTED | T1049 | ✓ |
| network.proxy | Proxy Configuration | Network | Both | User | IMPLEMENTED | T1016 | ✓ |
| network.routes | Route Table | Network | Both | User | IMPLEMENTED | T1016 | ✓ |
| network.routing_table | Routing Table | Network | Both | User | IMPLEMENTED | T1016 | ✓ |
| network.shares | Network Shares | Network | Both | User | IMPLEMENTED | T1021 | ✓ |
| network.tcp | TCP Connections | Network | Both | User | IMPLEMENTED | T1049 | ✓ |
| network.udp | UDP Connections | Network | Both | User | IMPLEMENTED | T1049 | ✓ |
| network.vpn | VPN Metadata | Network | Both | User | IMPLEMENTED | T1016 | ✓ |
| persistence.appinit | AppInit | Persistence | Windows | User | IMPLEMENTED | T1546 | ✓ |
| persistence.autostart | Autostart Entries | Persistence | Both | User | IMPLEMENTED | T1547 | ✓ |
| persistence.cron | Cron Entries | Persistence | Linux | User | IMPLEMENTED | T1053 | ✓ |
| persistence.ifeo | IFEO | Persistence | Windows | User | IMPLEMENTED | T1546 | ✓ |
| persistence.run | Run Keys | Persistence | Windows | User | IMPLEMENTED | T1547 | ✓ |
| persistence.scheduled.task | Scheduled Tasks | Persistence | Both | User | IMPLEMENTED | T1053 | ✓ |
| persistence.scheduled_tasks | Scheduled Tasks | Persistence | Both | User | IMPLEMENTED | T1053 | ✓ |
| persistence.shell.profile | Shell Profiles | Persistence | Both | User | IMPLEMENTED | T1547 | ✓ |
| persistence.ssh | SSH Persistence | Persistence | Linux | User | IMPLEMENTED | T1098 | ✓ |
| persistence.startup.folder | Startup Folder | Persistence | Both | User | IMPLEMENTED | T1547 | ✓ |
| persistence.systemd.timer | Systemd Timers | Persistence | Linux | User | IMPLEMENTED | T1053 | ✓ |
| persistence.winlogon | Winlogon | Persistence | Windows | User | IMPLEMENTED | T1547 | ✓ |
| persistence.wmi | WMI Event Subscriptions | Persistence | Windows | Admin | IMPLEMENTED | T1546 | ✓ |
| process.cgroup | CGroup | Process | Both | User | IMPLEMENTED | T1057 | ✓ |
| process.child.pids | Child PIDs | Process | Both | User | IMPLEMENTED | T1057 | ✓ |
| process.command_line | Command Line | Process | Both | User | IMPLEMENTED | T1057 | ✓ |
| process.container | Container ID | Process | Both | User | IMPLEMENTED | T1057 | ✓ |
| process.cwd | Working Directory | Process | Both | User | IMPLEMENTED | T1057 | ✓ |
| process.deleted.exe | Deleted Executable | Process | Linux | User | IMPLEMENTED | T1036 | ✓ |
| process.deleted_exe | Deleted Executable Detection | Process | Linux | User | IMPLEMENTED | T1036 | ✓ |
| process.enumerate | Process Enumeration | Process | Both | User | IMPLEMENTED | T1057 | ✓ |
| process.env | Environment | Process | Both | User | IMPLEMENTED | T1057 | ✓ |
| process.executable_path | Executable Path | Process | Both | User | IMPLEMENTED | T1057 | ✓ |
| process.group | Process Group | Process | Both | User | IMPLEMENTED | T1057 | ✓ |
| process.handles | Process Open Handles | Process | Both | Admin | IMPLEMENTED | T1057 | ✓ |
| process.hash | Executable Hash | Process | Both | User | IMPLEMENTED | T1027 | ✓ |
| process.integrity | Integrity Level | Process | Both | User | IMPLEMENTED | T1057 | ✓ |
| process.memory | Process Memory Regions | Process | Linux | User | IMPLEMENTED | T1055 | ✓ |
| process.memory.map | Memory Regions | Process | Linux | User | IMPLEMENTED | T1055 | ✓ |
| process.memory.rss | RSS Memory | Process | Both | User | IMPLEMENTED | T1057 | ✓ |
| process.memory.vms | Virtual Memory | Process | Both | User | IMPLEMENTED | T1057 | ✓ |
| process.module.list | Loaded Modules | Process | Both | User | IMPLEMENTED | T1014 | ✓ |
| process.module.path | Module Paths | Process | Both | User | IMPLEMENTED | T1014 | ✓ |
| process.module.signature | Module Signatures | Process | Both | User | IMPLEMENTED | T1014 | ✓ |
| process.module.version | Module Versions | Process | Both | User | IMPLEMENTED | T1014 | ✓ |
| process.modules | Process Modules/DLLs | Process | Both | User | IMPLEMENTED | T1057, T1014 | ✓ |
| process.name | Process Name | Process | Both | User | IMPLEMENTED | T1057 | ✓ |
| process.network.connections | Process Network | Process | Both | User | IMPLEMENTED | T1049 | ✓ |
| process.nice | Nice Value | Process | Both | User | IMPLEMENTED | T1057 | ✓ |
| process.open.files | Open Files | Process | Both | User | IMPLEMENTED | T1057 | ✓ |
| process.parent.name | Parent Name | Process | Both | User | IMPLEMENTED | T1057 | ✓ |
| process.pid | Process ID | Process | Both | User | IMPLEMENTED | T1057 | ✓ |
| process.ppid | Parent PID | Process | Both | User | IMPLEMENTED | T1057 | ✓ |
| process.priority | Priority | Process | Both | User | IMPLEMENTED | T1057 | ✓ |
| process.session | Session ID | Process | Both | User | IMPLEMENTED | T1057 | ✓ |
| process.start_time | Start Time | Process | Both | User | IMPLEMENTED | T1057 | ✓ |
| process.state | Process State | Process | Both | User | IMPLEMENTED | T1057 | ✓ |
| process.terminal | Terminal | Process | Both | User | IMPLEMENTED | T1057 | ✓ |
| process.threads | Thread Count | Process | Both | User | IMPLEMENTED | T1057 | ✓ |
| process.tree | Process Tree & Relationships | Process | Both | User | IMPLEMENTED | T1057 | ✓ |
| process.user | Process User | Process | Both | User | IMPLEMENTED | T1057 | ✓ |
| script.bash.metadata | Bash Metadata | MaliciousScript | Linux | User | IMPLEMENTED | T1059.004 | ✓ |
| script.cmd.metadata | CMD Metadata | MaliciousScript | Windows | User | IMPLEMENTED | T1059.003 | ✓ |
| script.environment.indicators | Environment Indicators | MaliciousScript | Both | User | IMPLEMENTED | T1059 | ✓ |
| script.execution | Execution Indicators | MaliciousScript | Both | User | IMPLEMENTED | T1059 | ✓ |
| script.file.indicators | File Path Indicators | MaliciousScript | Both | User | IMPLEMENTED | T1059 | ✓ |
| script.ip.indicators | IP Indicators | MaliciousScript | Both | User | IMPLEMENTED | T1059 | ✓ |
| script.javascript.metadata | JavaScript Metadata | MaliciousScript | Both | User | IMPLEMENTED | T1059.007 | ✓ |
| script.obfuscation | Obfuscation Indicators | MaliciousScript | Both | User | IMPLEMENTED | T1059 | ✓ |
| script.persistence | Persistence Indicators | MaliciousScript | Both | User | IMPLEMENTED | T1547 | ✓ |
| script.powershell | PowerShell Script Analysis | MaliciousScript | Windows | User | IMPLEMENTED | T1059.001 | ✓ |
| script.powershell.metadata | PowerShell Metadata | MaliciousScript | Windows | User | IMPLEMENTED | T1059.001 | ✓ |
| script.python | Python Script Analysis | MaliciousScript | Both | User | IMPLEMENTED | T1059.006 | ✓ |
| script.python.metadata | Python Metadata | MaliciousScript | Both | User | IMPLEMENTED | T1059.006 | ✓ |
| script.shell | Shell Script Analysis | MaliciousScript | Linux | User | IMPLEMENTED | T1059.004 | ✓ |
| script.url.indicators | URL Indicators | MaliciousScript | Both | User | IMPLEMENTED | T1059 | ✓ |
| script.wmi | WMI/VBScript Analysis | MaliciousScript | Windows | User | IMPLEMENTED | T1059.005 | ✓ |
| security.antivirus | AV Inventory | SecurityConfig | Both | User | IMPLEMENTED | T1562 | ✓ |
| security.app_control | Application Control | SecurityConfig | Both | Admin | IMPLEMENTED | T1562 | ✓ |
| security.apparmor | AppArmor State | SecurityConfig | Linux | User | IMPLEMENTED | T1562 | ✓ |
| security.audit.policy | Audit Policy | SecurityConfig | Both | Admin | IMPLEMENTED | T1562 | ✓ |
| security.audit_policy | Audit Policy | SecurityConfig | Both | Admin | IMPLEMENTED | T1562 | ✓ |
| security.av_status | Antivirus/EDR Status | SecurityConfig | Both | User | IMPLEMENTED | T1562 | ✓ |
| security.firewall | Firewall State | SecurityConfig | Both | Admin | IMPLEMENTED | T1562 | ✓ |
| security.policy | Security Policy | SecurityConfig | Both | Admin | IMPLEMENTED | T1562 | ✓ |
| security.selinux | SELinux State | SecurityConfig | Linux | User | IMPLEMENTED | T1562 | ✓ |
| security.update.state | Update State | SecurityConfig | Both | User | IMPLEMENTED | T1562 | ✓ |
| service.account | Service Account | Service | Both | User | IMPLEMENTED | T1543 | ✓ |
| service.binary.path | Service Binary | Service | Both | User | IMPLEMENTED | T1543 | ✓ |
| service.dependencies | Service Dependencies | Service | Both | User | IMPLEMENTED | T1543 | ✓ |
| service.driver.list | Driver Inventory | Service | Both | User | IMPLEMENTED | T1014 | ✓ |
| service.drivers | Kernel Drivers | Service | Both | User | IMPLEMENTED | T1014 | ✓ |
| service.enumerate | Service Enumeration | Service | Both | User | IMPLEMENTED | T1543 | ✓ |
| service.list | Service Inventory | Service | Both | User | IMPLEMENTED | T1543 | ✓ |
| service.name | Service Name | Service | Both | User | IMPLEMENTED | T1543 | ✓ |
| service.start.mode | Service Start Mode | Service | Both | User | IMPLEMENTED | T1543 | ✓ |
| service.state | Service State | Service | Both | User | IMPLEMENTED | T1543 | ✓ |
| service.systemd | Systemd Units | Service | Linux | User | IMPLEMENTED | T1543 | ✓ |
| service.systemd.units | Systemd Units | Service | Linux | User | IMPLEMENTED | T1543 | ✓ |
| system.architecture | Architecture | SystemInfo | Both | User | IMPLEMENTED | T1082 | ✓ |
| system.boot.time | Boot Time | SystemInfo | Both | User | IMPLEMENTED | T1082 | ✓ |
| system.cpu.cores | CPU Cores | SystemInfo | Both | User | IMPLEMENTED | T1082 | ✓ |
| system.cpu.count | CPU Count | SystemInfo | Both | User | IMPLEMENTED | T1082 | ✓ |
| system.cpu.frequency | CPU Frequency | SystemInfo | Both | User | IMPLEMENTED | T1082 | ✓ |
| system.cpu.model | CPU Model | SystemInfo | Both | User | IMPLEMENTED | T1082 | ✓ |
| system.disks | Disk Inventory | SystemInfo | Both | User | IMPLEMENTED | T1082 | ✓ |
| system.environment | Environment Variables | SystemInfo | Both | User | IMPLEMENTED | T1082 | ✓ |
| system.firmware.vendor | Firmware Vendor | SystemInfo | Both | User | IMPLEMENTED | T1082 | ✓ |
| system.firmware.version | Firmware Version | SystemInfo | Both | User | IMPLEMENTED | T1082 | ✓ |
| system.groups | System Groups | SystemInfo | Both | User | IMPLEMENTED | T1087 | ✓ |
| system.hostname | Hostname | SystemInfo | Both | User | IMPLEMENTED | T1082 | ✓ |
| system.info.basic | System Basic Info | SystemInfo | Both | User | IMPLEMENTED | T1082 | ✓ |
| system.info.detailed | System Detailed Info | SystemInfo | Both | User | IMPLEMENTED | T1082, T1012 | ✓ |
| system.info.users | System Users & Groups | SystemInfo | Both | User | IMPLEMENTED | T1087 | ✓ |
| system.kernel.version | Kernel Version | SystemInfo | Both | User | IMPLEMENTED | T1082 | ✓ |
| system.locale | Locale | SystemInfo | Both | User | IMPLEMENTED | T1082 | ✓ |
| system.machine.id | Machine ID | SystemInfo | Both | User | IMPLEMENTED | T1082 | ✓ |
| system.memory.boot | Boot Memory | SystemInfo | Both | User | IMPLEMENTED | T1082 | ✓ |
| system.memory.total | Total Memory | SystemInfo | Both | User | IMPLEMENTED | T1082 | ✓ |
| system.mounts | Mount Inventory | SystemInfo | Both | User | IMPLEMENTED | T1083 | ✓ |
| system.network.interfaces | Network Interfaces | SystemInfo | Both | User | IMPLEMENTED | T1082 | ✓ |
| system.os.name | OS Name | SystemInfo | Both | User | IMPLEMENTED | T1082 | ✓ |
| system.os.version | OS Version | SystemInfo | Both | User | IMPLEMENTED | T1082 | ✓ |
| system.packages | Package Inventory | SystemInfo | Both | User | IMPLEMENTED | T1082 | ✓ |
| system.partitions | Partition Inventory | SystemInfo | Both | User | IMPLEMENTED | T1082 | ✓ |
| system.paths | System Paths | SystemInfo | Both | User | IMPLEMENTED | T1082 | ✓ |
| system.secure.boot | Secure Boot | SystemInfo | Both | User | IMPLEMENTED | T1082 | ✓ |
| system.software.inventory | Software Inventory | SystemInfo | Both | User | IMPLEMENTED | T1082 | ✓ |
| system.timezone | Timezone | SystemInfo | Both | User | IMPLEMENTED | T1082 | ✓ |
| system.uptime | Uptime | SystemInfo | Both | User | IMPLEMENTED | T1082 | ✓ |
| system.users | System Users | SystemInfo | Both | User | IMPLEMENTED | T1087 | ✓ |
| system.virtualization | Virtualization | SystemInfo | Both | User | IMPLEMENTED | T1082 | ✓ |
| user.admin | Privileged Users | User | Both | User | IMPLEMENTED | T1078 | ✓ |
| user.enumerate | User Enumeration | User | Both | User | IMPLEMENTED | T1087 | ✓ |
| user.group.membership | Group Membership | User | Both | User | IMPLEMENTED | T1087 | ✓ |
| user.home | Home Directories | User | Both | User | IMPLEMENTED | T1087 | ✓ |
| user.last.login | Last Login | User | Both | User | IMPLEMENTED | T1087 | ✓ |
| user.list | User List | User | Both | User | IMPLEMENTED | T1087 | ✓ |
| user.service.accounts | Service Accounts | User | Both | User | IMPLEMENTED | T1078 | ✓ |
| user.shell | User Shell | User | Both | User | IMPLEMENTED | T1087 | ✓ |
| user.sid | User IDs | User | Both | User | IMPLEMENTED | T1087 | ✓ |
| user.status | Account Status | User | Both | User | IMPLEMENTED | T1087 | ✓ |
