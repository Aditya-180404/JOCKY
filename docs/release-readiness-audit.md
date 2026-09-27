# Release Readiness Audit

**Audit date:** 2026-09-27  
**Status:** RELEASE HARDENING INCOMPLETE

This report records behavior actually exercised in this workspace. It does not claim remote GitHub Actions jobs passed.

## Root Causes Found and Changes Made

| Finding | Change | Verification |
| --- | --- | --- |
| CI tamper probes appended invalid JSON, proving parse rejection rather than evidence integrity. | Linux and Windows CI now add a field to a record while preserving valid JSON. | Linux evidence was generated, verified, validly mutated, and rejected with a nonzero result. |
| Linux strict clippy failed on platform-specific unused parameters/imports and inefficient iterator/format patterns. | Fixed the reported findings in the artifacts, users, process, auth, and services runtime crates; strict warnings remain enabled. | Linux and Windows workspace fmt/clippy checks passed. |
| Download route sanitized untrusted paths and searched arbitrary repository/build files. | Restricted downloads to the ZIP, DEB, and EXE release names only. | API regression test rejects `Cargo.toml`, traversal variants, and arbitrary JSON; rebuilt API returned 404 for the same paths. |
| Same-version package URLs were marked immutable, allowing cached old bytes to be paired with new metadata. | Package routes use `Cache-Control: no-store`; the Web client keys requests by advertised SHA-256 and validates response type, filename, length, and hash. | Browser reproduced the stale ZIP mismatch before the fix; digest-keyed download then passed. |
| Download metadata could advertise absent packages with zero size or an `unavailable` hash and omitted MIME type. | Only existing, hashed artifacts are listed; metadata includes content type. | API invariant test and live download/hash checks passed for all three artifacts. |
| Web IDE lacked a separate VERIFY action and defaulted missing verification to `VALID`. | Added an API evidence-verification route and independent IDE VERIFY action; removed the false-valid fallback. | Browser CHECK, RUN (404 records), and independent VERIFY succeeded against the local API. |
| Capability matrix treated the API envelope as the capability map; negative suite hardcoded port 8080. | Updated envelope parsing and made both scripts accept an API base URL; negative CLI logs now go to unique temp files. | Capability matrix passed 12/12 and negative suite passed 10/10 against the release API on port 8081. |
| Capability `total` shrank when a filter was used. | `total` now describes the full registry while `count` describes filtered results. | API regression test confirms `count=241`, `total=247` for implemented-only filtering. |

## Verified Results

- Capability registry counts: 247 total, 241 implemented, 4 requiring elevation, 1 partial, 1 unsupported, 0 platform-specific.
- Windows host: `cargo fmt --all -- --check`, strict workspace clippy, full workspace tests, and release workspace build passed. The final API crate's 4 tests and strict clippy passed after its latest metadata test was added.
- Linux container: strict workspace clippy passed; workspace tests/release build completed and the native CLI generated an x86-64 ELF. A Linux investigation produced real evidence that passed SHA-256/Merkle verification; a valid-JSON edit was rejected.
- Windows ZIP: rebuilt from the release CLI; contains only `jockey.exe`; extracted in a clean temporary directory; PE signature and x86-64 machine `0x8664` verified; `--version`, `doctor`, and JSON capabilities commands ran.
- Debian package: rebuilt from the current release CLI; installed and removed in clean Ubuntu 24.04. `jockey --version`, `doctor`, capability export, and example validation ran after installation.
- Web: `npm run lint` and `npm run build` passed. Browser IDE CHECK, RUN, and independent VERIFY passed. Browser download buttons for ZIP, DEB, and EXE completed the client-side validation flow; the final rebuilt ZIP and DEB were rechecked after the stale-cache fix.
- Live release API: health, capability envelope, filters, package metadata, 404 traversal/unknown-name handling, correct MIME/disposition, and actual downloaded SHA-256 values were checked. Final artifact hashes are computed from local files and shown by `/api/downloads/info`.
- CRLF-aware `git diff --check` passed. Temporary validation containers and untracked build output created during testing were removed.

## Current Artifacts

| File | Size | SHA-256 | Validation |
| --- | ---: | --- | --- |
| `jockey_0.1.0_windows_amd64.zip` | 1,874,445 bytes | `2bfc7f87b802d9c63f1fa92c0a6e0a4ec0e15ea1b1c07ab586dc4f446325bee6` | ZIP contents, PE x64 header, extracted CLI smoke tests, API byte/hash match |
| `jockey_0.1.0_amd64.deb` | 1,564,168 bytes | `df3f242f73d62debaa31657fe0ff8a09d5c3afd10852915292d73cbdeafd97ec` | `dpkg-deb` inspection, clean Ubuntu install, CLI smoke tests, uninstall, API byte/hash match |
| `jockey.exe` | 4,624,384 bytes | `b1ebaf8f9937fa30a4c387d6ba0eb71fc2869c3493551ba0c208f447379e2846` | Executed from extracted ZIP; API byte/hash match |

## Remaining Release Blockers

1. Generated investigation projects embed an absolute runtime crate path derived from the compiler build tree (observed as `G:/jockey/runtime` in generated `Cargo.toml`). Packaged `jockey run`/compile is therefore not independent of the developer source tree and requires Rust/Cargo. A clean machine without Rust cannot run that workflow. This must be fixed before describing the CLI package as a self-contained forensic development platform.
2. Capability target compatibility is not a single compiler/backend contract. API CHECK rejects the tested Windows registry collector on Linux, but compilation and CLI target validation do not yet use the same complete per-capability platform matrix.
3. The 241 IMPLEMENTED entries were not individually exercised end-to-end across Windows and Linux. The runtime contract tests and representative system/process/network/filesystem runs do not certify every collector.
4. Remote GitHub Actions status was not queried. Local Windows and Docker/Linux equivalents passed, but Rust Linux, Rust Windows, Debian Package, and Web job results on GitHub remain unverified.
5. Playwright's browser-managed download event was not exposed for blob URLs in this environment. The browser click produced the verified-success UI state, and the exact bytes, headers, and SHA-256 were independently checked over HTTP.
6. `npm ci` on this Windows workspace hit `EPERM` while removing an in-use `esbuild.exe`; `npm install`, lint, and build passed. A clean Linux CI install was not separately executed here.

## Release Decision

**RELEASE HARDENING INCOMPLETE.** The items above are unresolved release acceptance criteria; this report does not certify production readiness.
