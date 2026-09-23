# TraceForge Language Specification (DSL)

TraceForge investigations are authored in declarative `.tfg` files. The language focuses on clear intent: what evidence to collect, how to filter it, and where to export the signed evidence artifact.

---

## 1. Syntax Overview

A TraceForge program consists of an `investigation` block containing `collect` and `export` statements, with optional filtering and metadata.

```traceforge
investigation "system_triage" {
    metadata {
        author: "Security Team"
        case_id: "INC-2026-09"
    }

    collect system_info

    collect processes where cpu_percent > 50 limit 20

    collect network_connections

    export evidence "system_triage.json"
}
```

---

## 2. Keywords and Statements

| Keyword | Description |
|---|---|
| `investigation` | Top-level block enclosing an entire forensic task |
| `metadata` | Key-value pairs providing forensic context (author, ticket, description) |
| `collect` | Specifies a collection target (`system_info`, `processes`, `network_connections`, `files`, `logs`) |
| `where` / `filter` | Filter expression evaluated on each item during collection |
| `limit` | Caps the number of records gathered |
| `export` | Defines the destination file and evidence envelope format |
| `evidence` | Canonical cryptographic evidence format |

---

## 3. Collection Targets

### `collect system_info`
Collects operating system telemetry:
- Hostname, OS name, version, architecture
- Kernel release, uptime, CPU count, total and available memory

### `collect processes`
Enumerates running processes:
- PID, PPID, executable name, full binary path
- Command line arguments
- Memory usage (RSS / virtual memory), CPU percentage
- User ID / username
- Binary SHA-256 hash (optional with `hash: "sha256"`)

### `collect network_connections`
Enumerates active network sockets:
- Protocol (`tcp`, `udp`)
- Local address and local port
- Remote address and remote port
- Socket state (`LISTEN`, `ESTABLISHED`, `TIME_WAIT`, `CLOSE_WAIT`)
- Associated process ID and process name

### `collect files [path]`
Traverses directory hierarchies:
- File paths, sizes, permissions, creation/modification timestamps
- SHA-256 cryptographic digests
- Options: `recursive: true`, `hash: "sha256"`, `limit: 100`

### `collect logs`
Extracts security log events:
- Platform log entries (syslog, journald, event log)
- Timestamps, log levels, source facilities, messages

---

## 4. Capabilities Inference

During semantic compilation, the compiler inspects all `collect` statements and infers the minimal required execution capabilities:

- `collect system_info` $\rightarrow$ `SystemInfoRead`
- `collect processes` $\rightarrow$ `ProcessRead`
- `collect network_connections` $\rightarrow$ `NetworkRead`
- `collect files` $\rightarrow$ `FilesystemRead`
- `collect logs` $\rightarrow$ `LogsRead`

These capabilities are embedded directly into the intermediate representation (IR) and artifact metadata.
