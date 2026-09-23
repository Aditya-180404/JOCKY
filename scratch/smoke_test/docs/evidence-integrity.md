# TraceForge Cryptographic Evidence Integrity

In digital forensics and incident response, evidence must withstand legal and technical scrutiny. TraceForge guarantees non-repudiation and tamper-evident provenance through multi-layered cryptographic assurance.

---

## 1. Evidence Envelope and Metadata Sidecars

When an investigation executes, it generates two files:

1. **Evidence File (`<name>.json`)**:
   Contains the collected forensic telemetry in a normalized, canonical JSON structure.

2. **Metadata Sidecar (`<name>.json.meta.json`)**:
   Contains cryptographic provenance data:
   - `artifact_hash`: The SHA-256 digest of the raw evidence payload.
   - `investigation`: The investigation identifier.
   - `host`: The machine hostname where collection was performed.
   - `collected_at`: RFC 3339 UTC timestamp.
   - `tool_version`: Compiler version used to generate the artifact.
   - `compiler_hash`: Binary hash of the compiling executable.
   - `source_hash`: Cryptographic hash of the `.tfg` script.

---

## 2. Merkle Tree Proofs

For multi-host or multi-artifact forensic campaigns, individual artifact hashes are combined into a Merkle tree:

```text
                  [ Merkle Root ]
                     /        \
          [ H(A + B) ]        [ H(C + D) ]
            /      \            /      \
        H(A)        H(B)    H(C)        H(D)
       Artifact 1  Artifact 2 Artifact 3 Artifact 4
```

- **Inclusion Proofs**: A single artifact can be cryptographically proven to belong to the overall investigation campaign without exposing or revealing other artifacts.
- **Root Anchoring**: The Merkle root is anchored into an immutable log or ledger.

---

## 3. Blockchain Anchoring Interface

TraceForge defines a pluggable `BlockchainAnchor` trait:

```rust
pub trait BlockchainAnchor: Send + Sync {
    fn anchor_evidence(&self, record: &AnchorRecord) -> Result<String, EvidenceError>;
    fn verify_anchor(&self, record: &AnchorRecord, anchor_ref: &str) -> Result<bool, EvidenceError>;
}
```

- **Development Adapter**: Provides in-memory or simulated cryptographic anchoring with nonces and block hashes for local testing and CI verification.
- **Enterprise Adapters**: Can be connected to Ethereum, Polygon, or enterprise distributed ledgers for legal non-repudiation.

---

## 4. Verification Workflow

Anyone holding an evidence file and sidecar can verify authenticity:

```powershell
traceforge verify system_triage.json
```

If even a single byte in `system_triage.json` is modified, the computed SHA-256 will diverge from the sidecar:

```text
Error: Artifact hash does not match any metadata file: c6979ab293168197b71750296ca5210f6b454da0ae7ad0381c13ad1d91a89ce3
```
Verification fails with exit code 1.
