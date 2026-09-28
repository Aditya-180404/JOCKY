# JOCKEY Cloud Transport Configuration

**Module:** `runtime/lotl/src/transport.rs`  
**Version:** 0.1.0 | **Date:** 2026-09-28

---

## Overview

JOCKEY field agents (compiled `.jy` investigation binaries) can deliver collected evidence to the central JOCKEY management interface through three transport modes:

| Mode | Network Profile | Detection Risk |
|---|---|:---:|
| `direct` | Plain HTTPS POST to known JOCKEY server | Medium — known server IP |
| `domain_fronted` | HTTPS via CDN; TLS SNI = trusted CDN host | Low — looks like normal CDN traffic |
| `socks5` | Encrypted tunnel through local/remote SOCKS5 proxy | Low — bypasses perimeter firewalls & direct routing |
| `cloud_api_relay` | HTTPS PUT to S3/GCS presigned URL; poll SQS/Pub-Sub | Very Low — indistinguishable from cloud storage I/O |

---

## DSL `config {}` Block

Transport settings are specified in the `.jy` investigation file's optional `config {}` block:

```jockey
investigation "incident_triage" {

    config {
        # Choose: "direct" | "domain_fronted" | "cloud_api_relay"
        transport = "domain_fronted"

        # The real JOCKEY management server URL
        relay_url = "https://jockey.your-org.com"

        # CDN hostname used for TLS SNI + HTTP Host header (domain_fronted only)
        cdn_host  = "cloudflare.com"

        # Timeout in seconds (default 30)
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
investigation "stealth_triage" {

    config {
        transport = "cloud_api_relay"

        # Presigned S3 PUT URL for evidence upload (obtained from JOCKEY API at registration)
        upload_url = "https://s3.amazonaws.com/jockey-evidence-bucket/uploads?X-Amz-Signature=..."

        # Presigned SQS GET URL for command polling
        poll_url = "https://sqs.us-east-1.amazonaws.com/123456789/jockey-cmds?AWSAccessKeyId=..."

        cloud_provider = "aws_s3"
    }

    collect system_info
    collect processes
    export evidence "stealth_triage.json"
}
```

---

## How Domain Fronting Works

```
Field Agent binary running on target machine
    │
    │  TLS handshake: SNI = "cloudflare.com"
    ▼
┌─────────────────────────┐
│  Cloudflare CDN Edge    │   ← Network IDS sees TLS to cloudflare.com (trusted)
│  (SNI: cloudflare.com)  │
└───────────┬─────────────┘
            │  Internal routing based on Host / X-Jockey-Target header
            ▼
┌─────────────────────────┐
│  JOCKEY Management API  │   ← Real destination, never visible on wire
│  jockey.your-org.com    │
└─────────────────────────┘
```

The key insight: **network-layer DLP and IDS only see the outer TLS SNI** (`cloudflare.com`), which is a trusted CDN used by millions of organisations. The inner HTTP headers routing the request to your JOCKEY server are encrypted inside TLS.

**Configuration requirements:**
1. Your JOCKEY API server must be accessible from the CDN's origin network (behind Cloudflare, CloudFront, or Fastly).
2. The CDN must be configured with an origin rule routing requests with `X-Jockey-Target: jockey.your-org.com` to your server.

---

## How Cloud API Relay Works

```
Field Agent binary
    │
    │  HTTPS PUT (presigned S3 URL)
    ▼
┌─────────────────────────────────────┐
│  AWS S3 Bucket (jockey-evidence)    │   ← Looks like app uploading a file to S3
└─────────────────────┬───────────────┘
                      │ S3 Event Notification
                      ▼
            ┌─────────────────┐
            │  AWS Lambda /   │
            │  JOCKEY Webhook │   ← Triggered by S3 object creation event
            └────────┬────────┘
                     ▼
            JOCKEY Management API
```

```
Field Agent binary
    │
    │  HTTPS GET (presigned SQS URL, long-poll)
    ▼
┌─────────────────────────────────────┐
│  AWS SQS Queue (jockey-commands)    │   ← Looks like app polling a message queue
└─────────────────────┬───────────────┘
                      │ Command message body
                      ▼
            Field Agent executes next investigation step
```

Traffic to `s3.amazonaws.com` and `sqs.us-east-1.amazonaws.com` appears as ordinary AWS service calls to network monitors. No custom server IP is ever contacted.

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
  "poll_presigned_url":   "https://sqs.us-east-1.amazonaws.com/...",
  "expires_in_secs": 3600
}
```

---

## Selecting a Transport for Your Scenario

| Scenario | Recommended Transport |
|---|---|
| Controlled lab, no adversary | `direct` |
| Incident response through corporate proxy | `domain_fronted` (CDN host = cloudflare.com) |
| Exfiltration through strict egress firewall (only 443 to trusted domains) | `domain_fronted` |
| Highly sensitive IR where server IP must never appear in logs | `cloud_api_relay` |
| Air-gapped network (offline collection) | N/A — use `export evidence` to file, transfer manually |
