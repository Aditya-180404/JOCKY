# TRACEFORGE — COMPLETE PROJECT DEVELOPMENT SPECIFICATION

You are the principal software architect, compiler engineer, backend engineer, frontend engineer, DevOps engineer, and security engineer responsible for building the project described below.

You are working on a real software repository. Do not merely describe code. Inspect the repository, create the required files, implement the features, run tests, diagnose failures, and iteratively improve the implementation.

The project name is currently:

TRACEFORGE

IMPORTANT:
The name is provisional. Do not hard-code the project name into architecture where it would make future renaming difficult.

---

# 1. PROJECT PURPOSE

TraceForge is a cloud-based digital-forensics development and distribution platform.

The platform introduces a domain-specific programming language for forensic investigations.

Investigators should be able to:

1. Open a web-based IDE.
2. Write forensic investigation programs using the TraceForge language.
3. Validate and compile the program.
4. Generate a portable forensic tool.
5. Version and publish the tool.
6. Store the tool in a centralized repository.
7. Download and reuse previously created tools.
8. Execute tools on authorized forensic/lab machines.
9. Collect forensic evidence.
10. Upload evidence to the platform.
11. Verify evidence integrity cryptographically.
12. View investigation results from a web dashboard.

The primary MVP is CLOUD-FIRST.

Do NOT make VPN infrastructure, remote network pivoting, reverse shells, or mandatory Windows/Linux agents part of the MVP.

Optional enterprise agents may be designed as a future extension.

---

# 2. IMPORTANT SECURITY BOUNDARY

This is a defensive digital-forensics platform.

The platform must NOT implement:

- antivirus/EDR bypass
- EDR tampering
- security-product disabling
- process hollowing
- reflective DLL injection
- thread hijacking
- API unhooking
- direct-syscall evasion
- BYOVD exploitation
- vulnerable-driver exploitation
- credential theft
- persistence mechanisms
- covert C2
- domain-fronting infrastructure
- malicious payload generation
- polymorphic malware generation
- stealth mechanisms intended to defeat security products

The original problem statement mentions these concepts, but TraceForge must interpret them from a defensive forensic perspective.

The compiler may perform normal optimization, deterministic/reproducible compilation, platform-specific compilation, and code generation.

Security and forensic operations must be explicit, auditable, permission-controlled, and reproducible.

---

# 3. CORE PRODUCT

Build these components:

TRACEFORGE PLATFORM

├── Web frontend
├── Web IDE
├── TraceForge language
├── TraceForge compiler
├── Compiler service
├── Tool repository
├── Tool/version management
├── Investigation management
├── Evidence management
├── Evidence integrity system
├── Authentication
├── Authorization/RBAC
├── Audit logging
└── API

Future components:

├── Windows Agent
├── Linux Agent
├── Enterprise deployment server
└── Private/on-premise deployment

The future components should have clean interfaces but do not allow them to delay the MVP.

---

# 4. RECOMMENDED HIGH-LEVEL ARCHITECTURE

Use this architecture:

                    TRACEFORGE CLOUD

                         Browser
                            |
             +--------------+--------------+
             |              |              |
             v              v              v
         Web IDE        Repository      Dashboard
             |              |              |
             +--------------+--------------+
                            |
                            v
                       REST API
                            |
             +--------------+--------------+
             |              |              |
             v              v              v
       Auth Service    Compiler Service   Investigation API
                            |
                            v
                       TraceForge IR
                            |
                            v
                         LLVM/backend
                            |
                  +---------+---------+
                  |                   |
                  v                   v
             Windows             Linux
               .exe               ELF
                  |                   |
                  +---------+---------+
                            |
                            v
                       Evidence
                            |
                            v
                     SHA-256 hashing
                            |
                            v
                       Merkle tree
                            |
                            v
                 Optional blockchain anchor

---

# 5. WEB APPLICATION

Build a modern web application.

Required pages:

/                     Landing page
/login                Authentication
/register             Registration
/dashboard            Main dashboard
/editor               TraceForge IDE
/repository           Tool repository
/repository/:id       Tool details
/investigations       Investigations
/investigations/:id   Investigation details
/evidence              Evidence
/evidence/:id         Evidence details
/settings              User settings
/admin                 Administrative dashboard

The UI should be professional and appropriate for cybersecurity/digital-forensics software.

Use a dark security/forensics-oriented interface but maintain readability and accessibility.

Do not create an excessive cyberpunk aesthetic.

---

# 6. WEB IDE

The IDE must contain:

- code editor
- syntax highlighting
- language selection
- file tree
- Run/Validate button
- Compile button
- Build target selector
- compiler output panel
- diagnostics panel
- generated artifact information
- SHA-256
- version information
- publish button

Example:

Target:

[ Windows x64 ]

or

[ Linux x64 ]

Buttons:

[Validate] [Compile] [Publish]

Output:

Compilation successful

Artifact:
process-triage.exe

SHA-256:
...

Compiler:
TraceForge Compiler 0.1.0

---

# 7. TRACEFORGE LANGUAGE

Create a small domain-specific language.

Do NOT attempt to create a full general-purpose language.

The language is specifically designed for forensic collection and investigation.

Example:

investigation "process_triage" {

    collect system_info

    collect processes {
        pid
        name
        parent
        command_line
        start_time
        hash.sha256
    }

    collect network_connections

    export evidence "process_triage.json"
}

Another example:

investigation "host_baseline" {

    collect system_info

    collect processes

    collect network_connections

    collect files "/tmp" {
        recursive true
        hash sha256
    }

    export evidence "baseline.json"
}

---

# 8. INITIAL LANGUAGE FEATURES

Implement these first:

collect system_info

collect processes

collect network_connections

collect files

collect logs

hash evidence

export evidence

filter

where

limit

metadata

investigation

The language should eventually support:

- variables
- conditions
- structured records
- filters
- functions
- reusable modules
- error handling

Do not implement unnecessary language features until the core DSL works.

---

# 9. LANGUAGE PIPELINE

Implement a real compiler pipeline:

Source
  |
Lexer
  |
Parser
  |
AST
  |
Semantic Analysis
  |
JOCKY/TraceForge IR
  |
Backend
  |
Target artifact

Use the following internal architecture:

frontend/
    lexer
    parser
    ast
    diagnostics

semantic/
    typechecker
    validator

ir/
    ir_definition
    ir_builder

backend/
    llvm
    windows
    linux

runtime/
    process
    network
    filesystem
    system
    logs
    evidence

Do not tightly couple the parser directly to OS-specific implementation.

---

# 10. IR

Create an intermediate representation.

Example:

{
  "version": "0.1",
  "investigation": "process_triage",
  "operations": [
    {
      "operation": "process.enumerate"
    },
    {
      "operation": "process.command_line"
    },
    {
      "operation": "process.sha256"
    },
    {
      "operation": "network.connections"
    }
  ],
  "integrity": {
    "algorithm": "SHA-256"
  }
}

The IR must be:

- deterministic
- versioned
- serializable
- testable
- independent of the web frontend

---

# 11. COMPILER

Create a command-line compiler:

traceforge

Example:

traceforge validate process_triage.tfg

traceforge compile process_triage.tfg --target windows-x64

traceforge compile process_triage.tfg --target linux-x64

traceforge build process_triage.tfg

traceforge inspect process_triage.tfg

traceforge hash process_triage.exe

The compiler should return useful diagnostics.

Example:

ERROR:
line 7:
unknown field 'foo' for process record

WARNING:
operation requires capability PROCESS_READ

---

# 12. FORENSIC RUNTIME

Create a safe runtime/library for supported forensic operations.

Initial modules:

runtime.system
runtime.process
runtime.network
runtime.filesystem
runtime.logs
runtime.evidence

Examples:

runtime.process.enumerate()

runtime.network.connections()

runtime.filesystem.hash()

runtime.system.info()

All operations must be read-only unless explicitly required by a legitimate forensic workflow.

---

# 13. CAPABILITY MODEL

Every forensic operation must have explicit capabilities.

Example:

PROCESS_READ
NETWORK_READ
FILESYSTEM_READ
LOG_READ
SYSTEM_INFO_READ
FILE_HASH

The tool metadata must contain its required capabilities.

Example:

Tool:

Windows Process Investigator

Capabilities:

PROCESS_READ
NETWORK_READ
FILE_HASH

The system must prevent a tool from silently obtaining capabilities it did not declare.

---

# 14. TOOL REPOSITORY

Create a repository similar conceptually to a package/tool repository.

Every tool must have:

- unique ID
- name
- description
- version
- author
- platform
- architecture
- source hash
- compiler version
- artifact hash
- capabilities
- creation date
- publication date
- signature status
- changelog

Example:

Windows Process Investigator

Version:
1.2.0

Platform:
Windows

Architecture:
x64

Capabilities:
PROCESS_READ
NETWORK_READ
FILE_HASH

Compiler:
TraceForge 0.1.0

SHA-256:
...

Status:
SIGNED

---

# 15. VERSIONING

Support semantic versioning.

Example:

1.0.0
1.1.0
1.1.1
2.0.0

Never overwrite an immutable published tool version.

A new build must create a new version.

Users must be able to inspect historical versions.

---

# 16. EVIDENCE SYSTEM

Evidence must have metadata.

Example:

Evidence ID:
EV-000001

Investigation:
INC-000001

Tool:
Windows Process Investigator

Tool version:
1.2.0

Host:
HOST-01

Collection time:
...

SHA-256:
...

Evidence size:
...

The platform must calculate SHA-256 for uploaded evidence.

---

# 17. MERKLE TREE

Implement optional evidence batching.

Example:

Evidence A → SHA256
Evidence B → SHA256
Evidence C → SHA256
Evidence D → SHA256

       ↓

Merkle tree

       ↓

Merkle root

Store the Merkle root with the investigation.

The actual evidence should NOT be placed on a blockchain.

Only integrity metadata or an anchor should be considered for blockchain storage.

---

# 18. BLOCKCHAIN INTEGRITY

Implement this as an optional module.

Interface:

BlockchainAnchor

Methods:

anchor(hash)

verify(hash)

get_transaction(hash)

For the MVP, create a mock/local ledger implementation.

Do not make the entire project dependent on a real blockchain network.

The demonstration must work without blockchain credentials.

---

# 19. DATABASE

Use a relational database.

Recommended:

PostgreSQL

Create models/tables for:

users
organizations
roles
projects
investigations
tools
tool_versions
builds
artifacts
evidence
evidence_hashes
audit_logs

Use migrations.

Do not store binary artifacts directly inside relational database rows.

Use object/file storage for artifacts.

---

# 20. OBJECT STORAGE

Abstract storage behind an interface.

Example:

ArtifactStorage

put()
get()
delete()
exists()
checksum()

The first implementation may use local filesystem storage for development.

The architecture must allow S3-compatible storage later.

---

# 21. AUTHENTICATION

Implement:

- registration
- login
- logout
- password hashing
- sessions or secure JWT strategy
- role-based authorization

Roles:

ADMIN
INVESTIGATOR
DEVELOPER
VIEWER

Do not store plaintext passwords.

---

# 22. MULTI-TENANCY

Organizations must be isolated.

A user belongs to an organization.

Tools, investigations, evidence, and projects must respect organization boundaries.

Example:

Organization A must never be able to query Organization B's evidence.

Enforce this server-side.

Do not rely only on frontend filtering.

---

# 23. AUDIT LOGGING

Record security-sensitive actions:

LOGIN
LOGOUT
CREATE_TOOL
COMPILE_TOOL
PUBLISH_TOOL
DOWNLOAD_TOOL
CREATE_INVESTIGATION
RUN_INVESTIGATION
UPLOAD_EVIDENCE
VERIFY_EVIDENCE
CHANGE_PERMISSION

Each event should contain:

timestamp
user
organization
action
resource
result
IP metadata where appropriate

---

# 24. API

Create a clean REST API.

Example endpoints:

POST /api/auth/register
POST /api/auth/login
POST /api/auth/logout

GET /api/tools
POST /api/tools
GET /api/tools/:id
GET /api/tools/:id/versions
POST /api/tools/:id/build
POST /api/tools/:id/publish

GET /api/investigations
POST /api/investigations
GET /api/investigations/:id

POST /api/evidence
GET /api/evidence/:id
POST /api/evidence/:id/verify

GET /api/audit-logs

Use OpenAPI documentation.

---

# 25. COMPILER SERVICE

The web platform must not execute arbitrary compiler jobs directly inside the main API process.

Create a compiler service/worker architecture.

Flow:

Browser
  |
  v
API
  |
  v
Build Job
  |
  v
Queue
  |
  v
Compiler Worker
  |
  v
Sandboxed build environment
  |
  v
Artifact
  |
  v
Artifact storage

Build jobs must have:

- timeout
- memory limit
- CPU limit
- filesystem isolation
- network restrictions
- job status
- build logs

Never allow submitted code to freely access the host system.

---

# 26. WEB EDITOR SECURITY

The web editor accepts user-controlled source code.

Therefore:

- sanitize displayed compiler output
- prevent XSS
- validate file names
- restrict upload size
- validate project structure
- never execute uploaded binaries in the web server
- compile in isolated workers
- enforce authentication
- enforce organization boundaries

---

# 27. FRONTEND TECHNOLOGY

Choose a modern maintainable stack.

Preferred:

React
TypeScript
Vite
Tailwind CSS

Use a proper component structure.

Do not create a single gigantic frontend file.

Suggested:

src/
    components/
    pages/
    layouts/
    hooks/
    services/
    api/
    types/
    editor/
    repository/
    dashboard/

Use Monaco Editor or another professional code editor for the TraceForge IDE.

---

# 28. BACKEND TECHNOLOGY

Choose a language appropriate for the platform.

Preferred:

Rust or TypeScript for backend services.

The compiler itself should be implemented in Rust.

The backend may also use Rust if practical.

Do not introduce unnecessary microservices.

For the MVP, a modular monolith + compiler worker is preferred.

---

# 29. COMPILER TECHNOLOGY

Use Rust for the TraceForge compiler.

Do NOT fork the entire Rust compiler unless there is a demonstrated technical reason.

Preferred architecture:

TraceForge frontend
      ↓
TraceForge AST
      ↓
TraceForge IR
      ↓
LLVM/backend integration

Reuse LLVM/compiler infrastructure where practical.

The purpose is to create a new forensic DSL, not a clone of Rust.

---

# 30. PROJECT STRUCTURE

Use a monorepo.

Suggested:

traceforge/
│
├── apps/
│   ├── web/
│   └── api/
│
├── compiler/
│   ├── lexer/
│   ├── parser/
│   ├── ast/
│   ├── semantic/
│   ├── ir/
│   ├── backend/
│   └── cli/
│
├── runtime/
│   ├── system/
│   ├── process/
│   ├── network/
│   ├── filesystem/
│   ├── logs/
│   └── evidence/
│
├── services/
│   └── compiler-worker/
│
├── packages/
│   ├── shared-types/
│   └── api-client/
│
├── examples/
│   ├── process-triage/
│   ├── network-triage/
│   └── system-baseline/
│
├── tests/
│
├── docs/
│
├── docker/
│
├── docker-compose.yml
├── README.md
└── LICENSE

Adapt this structure if the repository already has an established architecture.

---

# 31. DEVELOPMENT METHODOLOGY

Do NOT attempt to implement everything at once.

Work in phases.

PHASE 0:
Inspect repository.

PHASE 1:
Create architecture and project skeleton.

PHASE 2:
Implement TraceForge lexer/parser/AST.

PHASE 3:
Implement semantic validation.

PHASE 4:
Implement TraceForge IR.

PHASE 5:
Implement CLI compiler.

PHASE 6:
Implement forensic runtime.

PHASE 7:
Generate a working Linux artifact.

PHASE 8:
Implement Windows target/build pipeline.

PHASE 9:
Implement backend API.

PHASE 10:
Implement database.

PHASE 11:
Implement repository.

PHASE 12:
Implement web IDE.

PHASE 13:
Implement investigation dashboard.

PHASE 14:
Implement evidence integrity.

PHASE 15:
Implement authentication/RBAC/audit logs.

PHASE 16:
Integrate everything.

PHASE 17:
Testing and hardening.

Do not move to the next major phase while the current phase is fundamentally broken.

---

# 32. TEST-DRIVEN DEVELOPMENT

Every major compiler component must have tests.

Required tests:

lexer tests
parser tests
AST tests
semantic tests
IR tests
compiler tests
runtime tests
API tests
authentication tests
authorization tests
repository tests
evidence hashing tests
Merkle tests
frontend tests

Include:

unit tests
integration tests
end-to-end tests

---

# 33. FIRST DEMONSTRATION TARGET

The first complete vertical slice must support:

SOURCE:

investigation "process_triage" {

    collect system_info

    collect processes

    export evidence "processes.json"
}

Then:

Browser editor
      ↓
Save source
      ↓
Validate
      ↓
Compile
      ↓
Generate artifact
      ↓
Calculate SHA-256
      ↓
Publish tool
      ↓
Repository
      ↓
Download artifact
      ↓
Run locally
      ↓
Generate evidence
      ↓
Upload evidence
      ↓
Verify hash
      ↓
Display in dashboard

This vertical slice is more important than adding many unfinished features.

---

# 34. LOCAL DEVELOPMENT

The project must be runnable locally.

Provide:

docker-compose.yml

Services should include only what is necessary, such as:

frontend
backend
database
compiler-worker
object-storage/local-storage

Provide:

.env.example

Do not commit secrets.

Provide a one-command or minimal-command development setup.

Example:

docker compose up --build

or a documented equivalent.

---

# 35. DOCUMENTATION

Create:

README.md

docs/architecture.md

docs/language.md

docs/compiler.md

docs/api.md

docs/security.md

docs/development.md

docs/deployment.md

docs/threat-model.md

The documentation must explain:

What TraceForge is
Why it exists
Architecture
Language syntax
Compiler pipeline
Repository
Evidence integrity
Security model
Deployment
Future agent architecture

---

# 36. THREAT MODEL

Document threats including:

malicious source submission
malicious compiler input
artifact tampering
evidence tampering
cross-tenant access
stolen credentials
unauthorized tool execution
supply-chain compromise
malicious repository artifact
compiler worker escape
object-storage compromise

For each threat document:

asset
attacker
attack surface
mitigation
residual risk

---

# 37. FUTURE AGENT INTERFACE

Do not implement the agent as an MVP requirement.

However, define an interface so it can later exist.

Example:

Agent

register()
heartbeat()
receive_job()
verify_job()
execute_authorized_tool()
upload_evidence()
report_status()

Future architecture:

TraceForge Cloud
       |
       | authenticated outbound connection
       |
TraceForge Enterprise Gateway
       |
       +---- Windows Agent
       |
       +---- Linux Agent

Do not use pivoting or reverse shells as the mechanism.

---

# 38. REPRODUCIBILITY

Build metadata must contain:

source hash
compiler version
compiler hash
dependency information
target platform
target architecture
build timestamp
artifact SHA-256

Where practical, make builds reproducible.

---

# 39. SOFTWARE SUPPLY CHAIN

Generate an SBOM for released components.

Track:

dependencies
versions
licenses
hashes

Use dependency auditing tools where available.

---

# 40. CI/CD

Create CI workflows for:

lint
unit tests
integration tests
compiler tests
frontend tests
backend tests
security scanning
SBOM generation
build

Do not automatically publish production artifacts from untrusted pull requests.

---

# 41. ERROR HANDLING

Never silently swallow errors.

Errors must contain:

error code
human-readable message
technical context where safe
request/job ID

The frontend must display useful errors.

---

# 42. LOGGING

Use structured logging.

Example:

{
  "timestamp": "...",
  "level": "INFO",
  "service": "compiler-worker",
  "job_id": "...",
  "event": "build_completed",
  "artifact_hash": "..."
}

Never log:

passwords
tokens
private keys
sensitive credentials

---

# 43. DESIGN PRINCIPLE

Prefer:

simple
modular
testable
auditable
reproducible
secure

over:

clever
over-engineered
highly distributed
unnecessary abstraction

A functioning vertical slice is more valuable than 100 incomplete features.

---

# 44. YOUR OPERATING RULES AS THE CODING AGENT

When working on the repository:

1. Inspect the existing repository before making changes.

2. Do not overwrite working code without understanding it.

3. Before implementing a feature, identify:
   - files involved
   - dependencies
   - interfaces
   - tests required

4. Implement incrementally.

5. Run tests after meaningful changes.

6. If tests fail:
   - inspect the failure
   - identify the root cause
   - fix the implementation
   - rerun the relevant tests

7. Do not hide test failures.

8. Do not mark TODOs as completed.

9. Do not create fake implementations merely to make tests pass.

10. If an external dependency is unavailable, create a clean abstraction and a local/mock implementation where appropriate.

11. Never put secrets in source code.

12. Never expose credentials in logs.

13. Keep compiler, backend, frontend, runtime, and repository responsibilities separated.

14. Prefer small commits/changes.

15. Keep documentation synchronized with architecture changes.

---

# 45. RESPONSE FORMAT

For every development task:

First state:

CURRENT PHASE:
...

OBJECTIVE:
...

FILES TO CHANGE:
...

Then implement the changes.

After implementation report:

IMPLEMENTED:
...

TESTS:
...

RESULT:
PASS / PARTIAL / BLOCKED

NEXT STEP:
...

Do not claim something works unless you actually tested it.
y

---

# 46. START NOW

Do not immediately generate thousands of lines of code.

First:

1. Inspect the repository.
2. Determine whether an existing project exists.
3. Identify the current technology stack.
4. Identify available build tools.
5. Identify available runtimes.
6. Produce a concise implementation plan.
7. Create the initial project architecture.
8. Implement the smallest working TraceForge language vertical slice.
9. Test it.
10. Continue phase-by-phase.

The ultimate goal is a working, demonstrable TraceForge platform rather than a collection of disconnected code samples.

BEGIN.
