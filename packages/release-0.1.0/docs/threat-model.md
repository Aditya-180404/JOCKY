# TraceForge Threat Model & Security Boundaries

TraceForge is engineered for defensive security investigations. Its design explicitly enforces read-only behavior, least privilege, and tamper resistance.

---

## 1. Safety and Read-Only Constraints

| Potential Abuse Vector | TraceForge Design Mitigation |
|---|---|
| Malicious persistence | TraceForge has no persistence mechanisms; binaries run once, write evidence to the designated output, and exit cleanly. |
| In-memory tampering | Memory handles are opened strictly with query/read rights (`PROCESS_QUERY_LIMITED_INFORMATION`); no write or injection capabilities exist. |
| EDR / Antivirus bypass | TraceForge includes zero evasion, hook manipulation, or AMSI/ETW patching logic. Collection is transparent and auditable. |
| Host compromise via script | The TraceForge DSL is domain-specific and sandboxed; it contains no shell execution, code evaluation, or arbitrary execution primitives. |

---

## 2. Cryptographic Integrity Threats

| Threat Vector | Attack Scenario | Mitigation in TraceForge |
|---|---|---|
| Evidence tampering | Adversary modifies collected IP addresses or hashes to conceal attack traces. | `traceforge verify` recalculates the SHA-256 hash of the JSON payload and compares it to the signed `.meta.json` sidecar. Divergence immediately fails verification. |
| Metadata forgery | Adversary generates fake metadata sidecar claiming an evidence file was collected at a different time or host. | Sidecars link the source hash, compiler hash, and investigation name. In distributed deployments, sidecars are hashed into Merkle trees anchored to immutable ledgers. |
| Compiler poisoning | Tampered compiler produces compromised forensic binaries. | The compiler embeds its own binary hash (`compiler_hash`) and source hash (`source_hash`) into generated binaries and metadata. |

---

## 3. Web & API Security Controls

- **Authentication**: Passwords are hashed using state-of-the-art Argon2id with random salts.
- **Session Tokens**: Cryptographically signed JWT tokens with strict expiry and audience checks.
- **Multi-Tenancy**: Organization isolation enforced on every database query using `organization_id` foreign keys and scoped row-level security.
- **Audit Logging**: Every action (tool creation, version publish, evidence upload, investigation execution) writes an immutable record to the `audit_logs` table.
