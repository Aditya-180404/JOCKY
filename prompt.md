# TRACEFORGE — FULL-SCALE FORENSIC PROGRAMMING LANGUAGE & PLATFORM

You are the principal compiler engineer, cybersecurity engineer, digital-forensics engineer, backend engineer, frontend engineer, DevOps engineer, and software architect responsible for building this project.

You are working inside an actual software repository.

Do not merely explain what should be built.

Inspect the repository, design the architecture, implement the software, create files, run tests, diagnose failures, fix them, and continuously move the project toward a production-quality working system.

The project is a direct implementation of the supplied cybersecurity/digital-forensics problem statement.

The product must not be reduced to merely a web dashboard.

The actual product consists of:

1. A new forensic programming language.
2. A compiler/toolchain for Windows and Linux.
3. A web-based development environment.
4. A downloadable standalone compiler.
5. A forensic script/tool repository.
6. A cloud-based investigation management platform.
7. Multi-system forensic analysis.
8. Security-analysis capabilities corresponding to the techniques described in the problem statement.
9. Evidence integrity and blockchain anchoring.
10. CI/CD and reproducible tool generation.

The project name is currently:

TRACEFORGE

Treat this as a provisional product name and keep naming configurable.

---

# 1. CORE PRODUCT VISION

TraceForge is a domain-specific programming language and forensic analysis platform for creating, compiling, distributing, executing, and managing computer and network forensic investigations.

The system has TWO equal execution models.

## MODEL A — LOCAL

A user downloads the TraceForge compiler from the website.

They install it on Windows or Linux.

They can then write:

process_triage.tfg

and compile locally:

Linux:

./traceforge process_triage.tfg -o process_triage

Windows:

traceforge.exe process_triage.tfg -o process_triage.exe

Explicit targets:

./traceforge process_triage.tfg 
    --target linux-x64 
    -o process_triage

./traceforge process_triage.tfg 
    --target windows-x64 
    -o process_triage.exe

The generated forensic tool can then be executed in the user's authorized forensic/lab environment.

The user does NOT need the cloud platform to compile their language.

---

# 2. MODEL B — CLOUD

The same language and compiler must be available through the TraceForge web platform.

Browser:

Web IDE
   ↓
TraceForge source
   ↓
Cloud compiler
   ↓
Build artifact
   ↓
Repository
   ↓
Download
   ↓
Local execution

The cloud platform additionally provides:

- collaboration
- tool repository
- version management
- investigations
- evidence management
- centralized analysis
- organization management
- audit logs
- integrity verification
- multi-host management
- optional agent architecture

The local compiler and cloud compiler MUST use the same language specification and compiler implementation.

There must not be two incompatible TraceForge languages.

---

# 3. PROBLEM-STATEMENT MAPPING

The supplied problem statement requires:

- independent/custom programming language
- LLVM/custom IR concepts
- cross-platform compiler
- computer forensics
- network forensics
- malicious-activity analysis
- polymorphic/generated representations
- CI/CD
- custom cryptographic mechanisms
- in-memory execution concepts
- process injection concepts
- API monitoring/unhooking concepts
- direct syscall concepts
- BYOVD concepts
- kernel-level security concepts
- central management
- multiple-system analysis
- cloud/CDN communication
- blockchain
- evidence integrity

TraceForge must provide a corresponding implementation or defensive forensic-analysis module for every major area.

Where a technique in the source statement represents security-evasion or kernel-subversion behavior, implement the corresponding capability as:

- detection
- forensic acquisition/analysis
- controlled laboratory simulation
- telemetry generation
- threat research
- defensive validation

Do NOT implement mechanisms whose purpose is to disable security products, evade EDR/AV, exploit vulnerable drivers, steal credentials, or conceal malicious activity on real systems.

The product should demonstrate that it understands and analyzes those techniques rather than becoming a malware/evasion framework.

---

# 4. LANGUAGE

Create a real programming language called TraceForge.

File extension:

.tfg

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

investigation "network_triage" {

    collect network_connections {
        local_address
        local_port
        remote_address
        remote_port
        protocol
        process
    }

    analyze suspicious_connections

    export evidence "network.json"
}

---

# 5. LANGUAGE PHILOSOPHY

TraceForge is NOT intended to replace Rust, C, C++, Python, or Go.

It is a domain-specific language optimized for:

- digital forensics
- incident response
- system investigation
- network investigation
- evidence collection
- timeline analysis
- threat detection
- forensic reporting

The language should make complex forensic operations simple.

Example:

collect processes

should translate into the appropriate platform-specific implementation.

---

# 6. LANGUAGE FEATURES

Initial syntax must support:

investigation

collect

analyze

filter

where

if

for

function

module

export

hash

timeline

alert

metadata

target

capability

evidence

report

Future syntax may include:

variables
arrays
objects
conditions
loops
functions
modules
imports
error handling

Do not add unnecessary language complexity before the core language is functional.

---

# 7. COMPILER ARCHITECTURE

Implement a real compiler.

Pipeline:

TraceForge source
       ↓
Lexer
       ↓
Parser
       ↓
AST
       ↓
Semantic analysis
       ↓
TraceForge IR
       ↓
Backend
       ↓
Native executable

The architecture must be:

frontend/
    lexer/
    parser/
    ast/
    diagnostics/

semantic/
    analyzer/
    typechecker/
    capability_checker/

ir/
    definitions/
    builder/
    serializer/

backend/
    llvm/
    windows/
    linux/

runtime/
    system/
    process/
    network/
    filesystem/
    logs/
    memory/
    evidence/
    timeline/

cli/

---

# 8. LLVM

Use LLVM as the machine-code generation infrastructure where practical.

The team must NOT unnecessarily fork the entire Rust compiler.

Preferred:

TraceForge frontend
       ↓
TraceForge AST
       ↓
TraceForge IR
       ↓
LLVM IR
       ↓
LLVM
       ↓
Native artifact

The compiler itself should be written in Rust.

---

# 9. STANDALONE COMPILER

The downloadable compiler is a FIRST-CLASS product component.

The website must provide downloads for:

TraceForge Compiler — Windows x64
TraceForge Compiler — Linux x64

Future:

Windows ARM64
Linux ARM64
macOS

The compiler package should contain:

traceforge
standard library/runtime
documentation
example .tfg programs
license
version metadata

---

# 10. CLI DESIGN

The CLI must support:

traceforge --help

traceforge --version

traceforge check script.tfg

traceforge compile script.tfg

traceforge build script.tfg

traceforge run script.tfg

traceforge inspect script.tfg

traceforge fmt script.tfg

traceforge hash artifact

traceforge target list

Examples:

./traceforge process.tfg -o process

./traceforge process.tfg 
    --target linux-x64 
    -o process

./traceforge process.tfg 
    --target windows-x64 
    -o process.exe

Compilation output:

TraceForge Compiler 0.1.0

Source:
process.tfg

Target:
linux-x64

Capabilities:
PROCESS_READ
SYSTEM_INFO_READ

Compilation:
SUCCESS

Output:
./process

SHA-256:
...

---

# 11. COMPILER INSTALLATION

Provide installation methods.

Linux:

tar archive
installer script where appropriate
optional package

Windows:

.zip
installer

The website must provide:

Download compiler
Documentation
Release notes
Checksums
Signature information

Users must be able to verify the downloaded compiler.

---

# 12. REPRODUCIBLE BUILDS

Every compiler build must have:

version
source commit
compiler hash
dependency versions
target platform
target architecture
build metadata
artifact SHA-256

Where practical, support reproducible builds.

---

# 13. FORENSIC STANDARD LIBRARY

Create a TraceForge forensic standard library.

Modules:

system
process
network
filesystem
logs
memory
registry
persistence
timeline
hash
evidence
report

Examples:

system.info()

process.enumerate()

network.connections()

filesystem.hash(path)

logs.windows_events()

logs.journald()

timeline.create()

evidence.hash()

---

# 14. WINDOWS FORENSICS

Implement supported forensic collection using documented Windows interfaces and appropriate forensic mechanisms.

Initial capabilities:

system information
process enumeration
parent-child relationships
command lines
loaded modules
file metadata
SHA-256
network connections
Windows Event Logs
services
scheduled tasks
startup/persistence indicators
registry metadata where appropriate

The implementation must prioritize read-only forensic collection.

---

# 15. LINUX FORENSICS

Implement:

system information
/proc analysis
process enumeration
command lines
network sockets
filesystem metadata
SHA-256
journald
authentication logs
services
cron
startup mechanisms
kernel information

Again, prioritize read-only forensic collection.

---

# 16. NETWORK FORENSICS

Provide:

connection enumeration
local/remote addresses
ports
protocol
process association
DNS information where available
network timeline
connection filtering
suspicious connection analysis

Support investigation queries such as:

collect network_connections

where remote_port == 4444

export evidence "connections.json"

---

# 17. MALICIOUS-ACTIVITY ANALYSIS

TraceForge must include forensic detection modules for suspicious behavior.

Examples:

suspicious parent-child process relationships
unsigned processes
unexpected executable locations
suspicious network connections
unusual process memory characteristics
unusual thread start addresses
unexpected loaded modules
persistence mechanisms
suspicious drivers
known vulnerable drivers
abnormal privilege changes
suspicious command-line arguments

Results should include:

indicator
severity
evidence
reason
timestamp
host
process
confidence

---

# 18. MEMORY / IN-MEMORY EXECUTION ANALYSIS

The problem statement mentions fileless execution and techniques such as:

process hollowing
reflective loading
thread hijacking
API unhooking
direct system calls

TraceForge must provide a forensic-analysis layer capable of identifying indicators associated with these techniques.

Examples:

memory-region analysis
executable private memory detection
memory protection anomalies
thread start-address analysis
module mapping analysis
unexpected executable regions
suspicious process relationships

The platform may include controlled laboratory demonstrations that generate benign telemetry for these techniques.

Do not create real-world EDR bypass or stealth execution functionality.

---

# 19. DRIVER / BYOVD ANALYSIS

The problem statement explicitly mentions BYOVD and vulnerable drivers.

TraceForge must implement a driver-security analysis module.

Capabilities:

enumerate loaded drivers
collect driver names
versions
paths
signatures
hashes
publisher information
load times where available

Identify potentially vulnerable drivers using a maintained vulnerability database/signature set.

Produce:

Driver:
example.sys

SHA-256:
...

Publisher:
...

Version:
...

Security status:
Potentially vulnerable

Recommended action:
Investigate/remove/update

Do NOT exploit the driver.

Do NOT disable EDR.

Do NOT manipulate kernel structures.

---

# 20. SECURITY-PRODUCT TELEMETRY

Implement defensive analysis of security-product behavior.

Where available, collect/analyze:

security events
EDR alerts
AV events
driver events
process events
Windows event telemetry
Linux audit telemetry

Correlate these with forensic observations.

---

# 21. POLYMORPHISM / CODE-VARIATION RESEARCH MODULE

The problem statement discusses polymorphic generation.

TraceForge must provide a safe research implementation that demonstrates representation variation without generating malware or bypassing security products.

Possible features:

AST normalization
IR transformation
equivalent-code generation for benign programs
different optimization profiles
symbol/layout variation
deterministic build profiles
binary-diff analysis

Example:

Same TraceForge program:

process.tfg

Build A:
Profile: forensic-debug

Build B:
Profile: forensic-release

The system can demonstrate how generated representations differ while maintaining:

source identity
build provenance
signature
artifact hash
reproducibility metadata

The purpose is research and compiler engineering, not security-evasion payload generation.

---

# 22. CRYPTOGRAPHY

Implement cryptography for:

evidence integrity
artifact integrity
authentication
signatures
secure transport
tool verification

Use established cryptographic libraries.

Do NOT invent cryptographic algorithms.

Use:

SHA-256 for hashing

modern digital signatures

TLS/mTLS where appropriate

secure password hashing

---

# 23. TOOL SIGNING

Every published TraceForge tool should be signed.

Metadata:

tool_id
version
source_hash
artifact_hash
compiler_version
capabilities
signature
publisher
timestamp

Before execution, the local CLI should be able to verify the artifact.

Example:

traceforge verify process.exe

Result:

Signature:
VALID

Artifact hash:
VALID

Publisher:
TraceForge Repository

Version:
1.2.0

---

# 24. TOOL REPOSITORY

Create a central repository.

Users can:

search tools
browse categories
view versions
view source
view capabilities
view signatures
view hashes
download tools
publish tools
deprecate versions

Categories:

Process Analysis
Network Forensics
Windows Forensics
Linux Forensics
Log Analysis
Memory Analysis
Persistence Analysis
Malware Triage
File Analysis
Timeline Analysis

---

# 25. CLOUD COMPILER

The web IDE must use the same compiler implementation as the standalone CLI.

Architecture:

Web IDE
   ↓
API
   ↓
Compiler Worker
   ↓
TraceForge Compiler
   ↓
Artifact
   ↓
Repository

The compiler worker must execute inside an isolated build environment.

Never compile untrusted code directly inside the main API process.

---

# 26. CENTRAL MANAGEMENT

The cloud platform must support multiple authorized systems.

Conceptually:

TraceForge Cloud
       |
       +--- Organization A
       |       |
       |       +--- Host 1
       |       +--- Host 2
       |
       +--- Organization B
               |
               +--- Host 1
               +--- Host 2

The first MVP may use manually uploaded evidence.

Then implement optional agents.

---

# 27. OPTIONAL AGENT ARCHITECTURE

The agent is OPTIONAL.

It must NOT be required for the basic product.

The future architecture:

TraceForge Cloud
       |
       | authenticated outbound connection
       |
Organization Gateway
       |
       +--- Windows Agent
       +--- Linux Agent

The agent should:

register
authenticate
heartbeat
receive authorized investigation jobs
verify tool signature
check capabilities
execute approved forensic tool
collect evidence
hash evidence
upload evidence
report status

Do not use pivoting, reverse shells, or covert tunnels.

---

# 28. VPN

VPN is OPTIONAL.

TraceForge must not require organizations to build custom VPN infrastructure.

The architecture should support:

direct HTTPS/mTLS
organization proxy
enterprise gateway
site-to-site VPN where the organization already has one

Do not make VPN a prerequisite for the MVP.

---

# 29. CLOUD/CDN COMMUNICATION

The original problem statement mentions trusted cloud infrastructure/CDNs and domain-fronting concepts.

TraceForge should instead use:

HTTPS
TLS
mTLS
standard cloud APIs
authenticated API endpoints
optional enterprise proxy

Do not implement domain-fronting or traffic concealment.

The system should be transparent and auditable.

---

# 30. INVESTIGATION MANAGEMENT

Investigators can create:

Investigation ID
Title
Description
Severity
Hosts
Tools
Evidence
Timeline
Analysts
Notes
Findings
Reports

Example:

INC-2026-001

Hosts:
WIN-01
WIN-02
LINUX-01

Tools:
Process Investigator v1.2
Network Investigator v1.1

Evidence:
EV-001
EV-002
EV-003

---

# 31. EVIDENCE INTEGRITY

Every evidence object must have:

Evidence ID
Investigation ID
Host
Tool
Tool version
Collection timestamp
SHA-256
Size
Metadata

Implement:

SHA-256
Merkle trees
integrity verification

---

# 32. BLOCKCHAIN

Blockchain is an integrity/timestamping layer.

Do NOT store forensic evidence itself on-chain.

Architecture:

Evidence
   ↓
SHA-256
   ↓
Evidence hashes
   ↓
Merkle Tree
   ↓
Merkle Root
   ↓
Blockchain Anchor

Implement a local/mock blockchain adapter first.

Create an abstraction:

BlockchainAnchor

Methods:

anchor()
verify()
lookup()

Allow a real blockchain implementation later.

---

# 33. WEB IDE

Build a professional IDE.

Components:

file explorer
Monaco editor
syntax highlighting
autocomplete
diagnostics
compiler output
terminal-like build output
target selector
capability display
artifact information
source hash
artifact hash
publish button

Example:

TARGET

[ Linux x64 ]

[ Windows x64 ]

BUILD

[ Validate ] [ Compile ] [ Publish ]

---

# 34. DASHBOARD

Dashboard should display:

active investigations
recent evidence
tool repository
builds
hosts
alerts
integrity status
compiler versions
tool versions

Use charts only where useful.

---

# 35. SECURITY ARCHITECTURE

Implement:

RBAC
organization isolation
capability-based tool permissions
signed artifacts
audit logs
secure sessions
TLS
input validation
rate limiting
secure file handling

Roles:

ADMIN
INVESTIGATOR
DEVELOPER
ANALYST
VIEWER

---

# 36. MULTI-TENANCY

Organization A must never access:

Organization B's tools
Organization B's evidence
Organization B's investigations
Organization B's hosts

Enforce isolation at the backend/database layer.

Never rely solely on frontend checks.

---

# 37. AUDIT LOGGING

Audit:

LOGIN
LOGOUT
CREATE_TOOL
BUILD_TOOL
PUBLISH_TOOL
DOWNLOAD_TOOL
CREATE_INVESTIGATION
EXECUTE_TOOL
UPLOAD_EVIDENCE
VERIFY_EVIDENCE
CHANGE_PERMISSION
CREATE_USER
DELETE_USER

Include:

timestamp
user
organization
resource
action
result

---

# 38. DATABASE

Use PostgreSQL.

Tables/models:

users
organizations
roles
projects
investigations
hosts
tools
tool_versions
builds
artifacts
evidence
evidence_hashes
merkle_roots
blockchain_anchors
audit_logs

Binary artifacts must use object storage rather than database BLOBs.

---

# 39. OBJECT STORAGE

Create an abstraction:

ArtifactStorage

Methods:

put()
get()
delete()
exists()
hash()

Development:

local filesystem or local object-storage emulator.

Production:

S3-compatible storage.

---

# 40. API

Create REST APIs.

Authentication:

POST /api/auth/register
POST /api/auth/login
POST /api/auth/logout

Compiler:

POST /api/builds
GET /api/builds/:id
GET /api/builds/:id/logs

Tools:

GET /api/tools
POST /api/tools
GET /api/tools/:id
GET /api/tools/:id/versions
POST /api/tools/:id/publish

Investigations:

GET /api/investigations
POST /api/investigations
GET /api/investigations/:id

Evidence:

POST /api/evidence
GET /api/evidence/:id
POST /api/evidence/:id/verify

Hosts:

GET /api/hosts
POST /api/hosts

Audit:

GET /api/audit-logs

Generate OpenAPI documentation.

---

# 41. CLI PACKAGE COMMANDS

In addition to compilation, the CLI should support repository interaction.

Examples:

traceforge login

traceforge search "process"

traceforge install process-investigator

traceforge list

traceforge info process-investigator

traceforge update

traceforge verify process-investigator

traceforge publish process-investigator

This allows TraceForge to function like a forensic developer ecosystem rather than merely a compiler.

---

# 42. EXAMPLE WORKFLOW

Developer:

Write:

process.tfg

Compile locally:

./traceforge process.tfg -o process

Run:

./process

Or compile Windows:

./traceforge process.tfg 
    --target windows-x64 
    -o process.exe

Publish:

./traceforge publish process

Another investigator:

traceforge search process

traceforge install process-investigator

traceforge run process-investigator

Evidence is generated.

The investigator uploads it to the cloud.

The cloud verifies:

tool identity
tool version
tool signature
evidence hash

Then:

SHA-256
   ↓
Merkle tree
   ↓
Blockchain anchor

---

# 43. CI/CD

Create automated CI/CD.

Pipeline:

Git commit
   ↓
Lint
   ↓
Unit tests
   ↓
Compiler tests
   ↓
Security tests
   ↓
Build
   ↓
Cross-platform build
   ↓
Artifact signing
   ↓
SHA-256
   ↓
SBOM
   ↓
Release

Every release should generate:

Linux compiler
Windows compiler
documentation
checksums
signature
SBOM

---

# 44. PROJECT STRUCTURE

Use a monorepo.

Suggested:

traceforge/

apps/
    web/
    api/

compiler/
    lexer/
    parser/
    ast/
    semantic/
    ir/
    backend/
    cli/

runtime/
    system/
    process/
    network/
    filesystem/
    logs/
    memory/
    evidence/
    timeline/

services/
    compiler-worker/

repository/
    client/
    server/

packages/
    shared-types/
    api-client/

examples/
    process-triage/
    network-triage/
    windows-forensics/
    linux-forensics/
    memory-analysis/

tests/

docs/

docker/

.github/

README.md
LICENSE

Adapt this to the existing repository if necessary.

---

# 45. TECHNOLOGY

Compiler:

Rust

Compiler backend:

LLVM

Frontend:

React
TypeScript
Vite
Tailwind CSS
Monaco Editor

Backend:

Rust or TypeScript

Database:

PostgreSQL

Object storage:

S3-compatible abstraction

Containerization:

Docker

CI:

GitHub Actions or equivalent

---

# 46. TESTING

Create tests for:

lexer
parser
AST
semantic analysis
IR
LLVM generation
CLI
runtime
Windows collector
Linux collector
network collector
evidence hashing
Merkle trees
signatures
repository
API
authentication
authorization
multi-tenancy
frontend
compiler worker

Create end-to-end tests for:

.tfg source
   ↓
compiler
   ↓
artifact
   ↓
execution
   ↓
evidence
   ↓
upload
   ↓
verification

---

# 47. FIRST COMPLETE VERTICAL SLICE

Do NOT attempt the entire system first.

The first complete working slice MUST be:

1. Write:

investigation "process_triage" {

    collect system_info

    collect processes

    export evidence "processes.json"
}

2. Save as:

process.tfg

3. Run:

./traceforge check process.tfg

4. Compile:

./traceforge process.tfg -o process

5. Execute:

./process

6. Generate:

processes.json

7. Calculate SHA-256.

8. Upload to cloud.

9. Display evidence in dashboard.

10. Verify evidence integrity.

11. Publish the compiled tool to the repository.

12. Download the same tool from the repository.

This vertical slice must work before expanding the system.

---

# 48. SECOND VERTICAL SLICE

Implement:

network.tfg

collect network_connections

Then:

compile
execute
collect
hash
upload
display
analyze

---

# 49. THIRD VERTICAL SLICE

Implement:

security_analysis.tfg

which analyzes:

process anomalies
network anomalies
suspicious modules
suspicious memory characteristics
driver information

The result must be a forensic report, not an evasion payload.

---

# 50. DOCUMENTATION

Create:

README.md
docs/architecture.md
docs/language.md
docs/compiler.md
docs/cli.md
docs/web-ide.md
docs/repository.md
docs/forensics.md
docs/security-analysis.md
docs/evidence-integrity.md
docs/blockchain.md
docs/agent.md
docs/api.md
docs/deployment.md
docs/development.md
docs/threat-model.md

---

# 51. THREAT MODEL

Document:

untrusted source code
malicious tool submissions
compiler worker compromise
artifact tampering
repository compromise
evidence tampering
credential compromise
cross-tenant access
malicious agents
supply-chain attacks
vulnerable dependencies

For each:

asset
attacker
attack surface
mitigation
residual risk

---

# 52. DOWNLOAD PAGE

Create a dedicated compiler download page.

Example:

TraceForge Compiler

Latest:
v0.1.0

Windows x64
[Download]

Linux x64
[Download]

SHA-256:
...

Signature:
...

Source:
...

Release notes:
...

Documentation:
...

The page must make clear that the compiler can operate independently of the cloud platform.

---

# 53. LOCAL-FIRST PRINCIPLE

A user must be able to use TraceForge without internet access after installing the compiler and runtime.

Local compilation:

.tfg
 ↓
TraceForge compiler
 ↓
native artifact

Cloud functionality is an enhancement, not a compiler dependency.

The local compiler must not require cloud authentication for normal compilation.

---

# 54. CLOUD-FIRST PLATFORM PRINCIPLE

The web platform provides:

IDE
repository
collaboration
investigations
central management
evidence
integrity
analytics
organization management

But the language itself remains portable.

---

# 55. NO ARTIFICIAL MOCKING

Do not create fake compiler output that merely looks like a binary.

If the system claims:

"compiled successfully"

there must actually be a generated executable or valid target artifact.

If LLVM support is temporarily unavailable, clearly report that the backend is incomplete rather than pretending it works.

---

# 56. NO FAKE FORENSICS

Do not generate random fake process/network/evidence data and call it forensic collection.

Development mocks are acceptable only when explicitly labeled as mocks.

Real local forensic collection must be implemented for supported platforms.

---

# 57. SECURITY RESEARCH BOUNDARY

The project must be capable of:

DETECTING
ANALYZING
CORRELATING
REPORTING
SIMULATING IN A CONTROLLED LAB

security techniques mentioned in the problem statement.

It must not become a tool for:

EDR bypass
AV bypass
security-product disabling
kernel compromise
credential theft
covert persistence
malware delivery
real-world exploit deployment

---

# 58. DEVELOPMENT WORKFLOW FOR THE CODING AGENT

Before modifying anything:

1. Inspect repository.
2. Identify existing files.
3. Identify language/toolchain.
4. Identify build system.
5. Identify tests.
6. Identify current implementation status.

Then provide:

CURRENT PHASE
OBJECTIVE
FILES TO CHANGE
IMPLEMENTATION PLAN

Then implement.

After implementation:

IMPLEMENTED
TESTS RUN
TEST RESULTS
KNOWN LIMITATIONS
NEXT PHASE

Never claim a feature is complete unless it was actually implemented and tested.

---

# 59. DO NOT BUILD EVERYTHING IN ONE RESPONSE

Implement incrementally.

Phase 0:
Repository inspection

Phase 1:
Monorepo and architecture

Phase 2:
TraceForge language

Phase 3:
Compiler + CLI

Phase 4:
Linux runtime

Phase 5:
Windows runtime

Phase 6:
Evidence subsystem

Phase 7:
Web API

Phase 8:
Database

Phase 9:
Repository

Phase 10:
Web IDE

Phase 11:
Dashboard

Phase 12:
Security-analysis modules

Phase 13:
Blockchain integrity

Phase 14:
CI/CD

Phase 15:
Optional agent architecture

Phase 16:
End-to-end testing

Phase 17:
Release packaging

---

# 60. FINAL ACCEPTANCE CRITERIA

The project is considered MVP-complete only when a user can perform this complete workflow:

LOCAL:

Download compiler
   ↓
Install compiler
   ↓
Create .tfg program
   ↓
Validate
   ↓
Compile
   ↓
Generate native executable
   ↓
Execute
   ↓
Collect forensic evidence
   ↓
Hash evidence

CLOUD:

Open TraceForge
   ↓
Write .tfg
   ↓
Compile
   ↓
View diagnostics
   ↓
Generate artifact
   ↓
Publish
   ↓
Repository
   ↓
Version
   ↓
Download
   ↓
Execute locally
   ↓
Upload evidence
   ↓
Verify integrity
   ↓
Investigation dashboard
   ↓
Merkle root
   ↓
Optional blockchain anchor

MULTI-HOST:

Cloud
   ↓
Authorized organization
   ↓
Authorized hosts
   ↓
Forensic tools
   ↓
Evidence
   ↓
Central analysis

---

# 61. START

Begin immediately.

Do NOT generate a massive fictional implementation.

First inspect the repository.

Then determine what already exists.

Then create the architecture.

Then implement the first working vertical slice:

.tfg
   ↓
lexer
   ↓
parser
   ↓
AST
   ↓
IR
   ↓
compiler
   ↓
native Linux executable
   ↓
real local forensic collection
   ↓
SHA-256 evidence
   ↓
cloud upload
   ↓
dashboard

After that works, implement Windows compilation/runtime and continue through the remaining phases.

The objective is a real, testable, demonstrable forensic programming ecosystem—not a prototype consisting of static UI screens.