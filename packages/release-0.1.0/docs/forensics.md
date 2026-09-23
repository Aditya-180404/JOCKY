# TraceForge Forensic Runtime Engine

The TraceForge forensic runtime engine is designed for zero-footprint, read-only system telemetry and artifact acquisition.

---

## 1. Safety and Zero-Footprint Guarantees

- **No In-Memory Modification**: Does not patch running code, hook kernel routines, or manipulate system memory.
- **No EDR/AV Tampering**: Does not disable security agents, alter audit policies, or manipulate event logs.
- **Read-Only Handles**: System APIs are opened strictly with query/read access (e.g. `PROCESS_QUERY_LIMITED_INFORMATION`, read-only file handles).
- **Stateless Binary Execution**: Standalone executable releases memory upon completion and leaves no persistent background services.

---

## 2. Platform Telemetry Collectors

### System Collector (`runtime/system`)
- Host identity: Machine hostname, domain membership, UUID.
- OS attributes: Operating system version, release kernel, architecture.
- Telemetry: Uptime, boot timestamp, logical CPU count, memory capacity, and free RAM.

### Process Collector (`runtime/process`)
- Process hierarchy: Process ID (PID), Parent Process ID (PPID).
- Process attributes: Executable binary path, full command line with arguments.
- Runtime performance: Resident Set Size (RSS), virtual memory size, CPU utilization.
- Cryptographic verification: Calculates on-disk executable SHA-256 hash when requested.

### Network Collector (`runtime/network`)
- Socket states: `LISTEN`, `ESTABLISHED`, `TIME_WAIT`, `CLOSE_WAIT`, `SYN_SENT`.
- Protocols: TCP, UDP over IPv4 and IPv6.
- Endpoints: Local address and port, remote address and port.
- Process correlation: Associates active sockets with the owning process PID and process name.

### Filesystem Collector (`runtime/filesystem`)
- Traversal: Bounded recursive or flat directory traversal.
- File metadata: File size, permissions/attributes, creation, modification, and access timestamps.
- Cryptographic integrity: Streaming SHA-256 computation over file content.

---

## 3. Security Analysis Module (`runtime/security`)

TraceForge includes an embedded forensic heuristic analyzer for detecting common indicators of compromise:

1. **Suspicious Parent-Child Spawns**: Detects script and shell engines (`cmd.exe`, `powershell.exe`, `wscript.exe`) spawned by Office or service processes.
2. **Suspicious Command-Line Invocations**: Identifies encoded commands, download cradles (`certutil -urlcache`, `Invoke-WebRequest`), and stealth flags.
3. **Suspicious Network Endpoints**: Flags connections over high-risk or uncommon ports (e.g. Metasploit/reverse shell defaults, 4444, 1337).
4. **Anomalous Process Executables**: Identifies executables launched from temporary or staging directories (`\AppData\Local\Temp`, `/tmp`).
