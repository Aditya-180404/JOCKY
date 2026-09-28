# JOCKEY Secure Transport Overview

**Module:** `runtime/lotl/src/transport.rs`  
**Version:** 0.1.0 | **Date:** 2026-09-28

---

## Overview

JOCKEY can deliver collected evidence to a central JOCKEY management service through a small set of approved transport modes. These are designed for legitimate forensic operations and must be used only in environments where the administrator has explicit authorization to gather and transmit evidence.

| Mode | Network Profile | Intended Use |
|---|---|---|
| `direct` | HTTPS POST to a known JOCKEY server | Normal managed evidence upload |
| `relay` | HTTPS upload through a trusted intermediary or proxy | Controlled enterprise routing |
| `socks5` | Routing through an approved SOCKS5 proxy | Environments with explicit proxy policy |
| `cloud_api_relay` | Upload to an approved object-store endpoint | Evidence handoff with validated service credentials |

This project does not endorse bypassing security controls, hiding traffic from an organization, or using covert channels for unauthorized collection.

---

## DSL `config {}` Block

Transport settings are specified in the `.jy` investigation file's optional `config {}` block:

```jockey
investigation "incident_triage" {

    config {
        transport = "direct"
        relay_url = "https://jockey.your-org.com"
        timeout = 60
    }

    collect system_info
    collect processes { pid, name, parent, hash.sha256 }
    collect network_connections
    export evidence "incident_triage_evidence.json"
}
```

### Cloud API Relay Example

```jockey
investigation "managed_triage" {

    config {
        transport = "cloud_api_relay"
        upload_url = "https://s3.amazonaws.com/jockey-evidence-bucket/uploads?X-Amz-Signature=..."
        cloud_provider = "aws_s3"
    }

    collect system_info
    collect processes
    export evidence "managed_triage.json"
}
```

---

## Transport Design Principles

The JOCKEY transport layer is meant to support operational realities, not evade detection or policy enforcement:

1. Use only approved, explicitly configured endpoints.
2. Respect enterprise proxy, firewall, and egress control policy.
3. Prefer transport modes that are already authorized by the host organization.
4. Require signed or authenticated evidence handoff whenever possible.
5. Retain auditable logs and evidence metadata for each transmission.

When a deployment requires a proxy or cloud relay, it should be an approved infrastructure component, not a covert channel.

---

## API Integration

The JOCKEY management API exposes endpoints for registering agents and issuing presigned URLs:

```http
POST /api/transport/register
Content-Type: application/json

{
  "agent_id": "host-abc123",
  "transport_kind": "cloud_api_relay",
  "cloud_provider": "aws_s3",
  "investigation_name": "incident_triage"
}
```

Response:
```json
{
  "upload_presigned_url": "https://s3.amazonaws.com/...",
  "expires_in_secs": 3600
}
```

---

## Selecting a Transport for Your Scenario

| Scenario | Recommended Transport |
|---|---|
| Internal investigation with direct network access | `direct` |
| Enterprise environment with managed proxy | `relay` |
| Approved SOCKS5 gateway in the environment | `socks5` |
| Cloud-based evidence handoff using approved object storage | `cloud_api_relay` |
| Air-gapped network | `export evidence` to file, transfer manually |
