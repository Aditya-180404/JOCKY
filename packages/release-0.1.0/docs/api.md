# TraceForge REST API Reference

The TraceForge backend API is built with Rust and Axum, offering high-performance, asynchronous endpoints for authentication, tool management, investigations, evidence ingestion, and audit trails.

---

## 1. Authentication Endpoints

### Register User
- **Method**: `POST`
- **Path**: `/api/v1/auth/register`
- **Body**:
  ```json
  {
    "username": "investigator",
    "email": "investigator@example.com",
    "password": "SecurePassword123!",
    "organization_name": "Cyber Defense Inc"
  }
  ```
- **Response**: `201 Created` with JWT session token.

### Login
- **Method**: `POST`
- **Path**: `/api/v1/auth/login`
- **Body**:
  ```json
  {
    "username": "investigator",
    "password": "SecurePassword123!"
  }
  ```
- **Response**: `200 OK` with JWT bearer token.

---

## 2. Tools & Compiler Endpoints

### List Tools
- **Method**: `GET`
- **Path**: `/api/v1/tools`
- **Headers**: `Authorization: Bearer <token>`
- **Response**: Array of published forensic tools with author, capabilities, and version count.

### Create Tool
- **Method**: `POST`
- **Path**: `/api/v1/tools`
- **Body**:
  ```json
  {
    "name": "network_triage",
    "description": "Collects active socket connections and listening ports",
    "capabilities": ["NetworkRead"]
  }
  ```

### Publish Tool Version
- **Method**: `POST`
- **Path**: `/api/v1/tools/:id/versions`
- **Body**:
  ```json
  {
    "version": "1.0.0",
    "source_code": "investigation \"net\" { collect network_connections export evidence \"net.json\" }",
    "changelog": "Initial release"
  }
  ```

---

## 3. Evidence Endpoints

### Ingest Evidence Artifact
- **Method**: `POST`
- **Path**: `/api/v1/evidence`
- **Body**:
  ```json
  {
    "investigation_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "host_id": "00000000-0000-0000-0000-000000000000",
    "artifact_name": "system_triage.json",
    "artifact_hash": "6ac32859e84870e29624e3c721717823867e6cd01e95412862a3a0f43b728a6a",
    "data": { ... }
  }
  ```

### Verify Evidence Integrity
- **Method**: `POST`
- **Path**: `/api/v1/evidence/:id/verify`
- **Response**:
  ```json
  {
    "verified": true,
    "calculated_hash": "6ac32859e84870e29624e3c721717823867e6cd01e95412862a3a0f43b728a6a",
    "recorded_hash": "6ac32859e84870e29624e3c721717823867e6cd01e95412862a3a0f43b728a6a",
    "tampered": false
  }
  ```
