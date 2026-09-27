# Capability Inventory and Verification Status

**Updated:** 2026-09-27  
**Registry source:** `runtime/capabilities/src/lib.rs`  
**Release status:** Inventory counts verified; full per-capability release certification remains incomplete.

## Registry Counts

The current runtime registry and CLI report:

| Status | Count |
| --- | ---: |
| Total | 247 |
| Implemented | 241 |
| Requires elevation | 4 |
| Partial | 1 |
| Platform-specific | 0 |
| Unsupported | 1 |

These are registry classifications, not proof that every capability has passed an end-to-end collection test on every supported operating system.

## Verification Performed

- `jockey capabilities` and `jockey capabilities --format json` reported 247 entries.
- `GET /api/compiler/capabilities` returned the `capabilities` envelope and status totals of 241/4/1/1.
- `?status=implemented` returned 241 entries while preserving `total: 247`.
- The capability matrix exercised all 17 categories and validated required metadata fields.
- The runtime capability crate tests passed, including its dispatch-map and known implementation contract tests.
- A Windows registry investigation checked for `RegistryRead` targeting `linux-x64` returns an error from the API CHECK endpoint.

## Limits of This Audit

This session did not individually execute all 241 implemented registry entries through CLI, API, and Web IDE on both operating systems. The current DSL target check includes a `RegistryRead` special case in the API checker; target validation is not yet a shared compiler/backend contract for every capability and can differ between CHECK and compilation. Do not treat the aggregate registry count as a substitute for that missing matrix.

`process.memory.map`, `file.elf_metadata`, `backdoor.rootkit_indicators`, `artifact.amcache`, `artifact.etw`, `artifact.srum`, `kernel.syscalls`, and `evidence.blockchain_anchor` require dedicated platform/privilege tests before their individual release status can be certified.

See [release-readiness-audit.md](release-readiness-audit.md) for current build, package, API, Web IDE, and release limitations.
