#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

mkdir -p build

echo "[1/3] Building polymorphic variant A"
./target/debug/jockey compile examples/process_triage.jy --output build/polymorph-a --polymorphic --cfg-flatten --encrypt-strings --junk-instructions --opaque-predicates >/tmp/jockey_poly_a.log 2>&1 || {
  echo "Build A failed" >&2
  cat /tmp/jockey_poly_a.log >&2
  exit 1
}
sha_a=$(sha256sum build/polymorph-a/*.ll 2>/dev/null | sha256sum | cut -d' ' -f1 || true)
if [ -z "$sha_a" ]; then
  sha_a=$(find build/polymorph-a -type f -exec sha256sum {} + | sha256sum | cut -d' ' -f1)
fi

sleep 1

echo "[2/3] Building polymorphic variant B"
./target/debug/jockey compile examples/process_triage.jy --output build/polymorph-b --polymorphic --cfg-flatten --encrypt-strings --junk-instructions --opaque-predicates >/tmp/jockey_poly_b.log 2>&1 || {
  echo "Build B failed" >&2
  cat /tmp/jockey_poly_b.log >&2
  exit 1
}
sha_b=$(find build/polymorph-b -type f -exec sha256sum {} + | sha256sum | cut -d' ' -f1)

sleep 1

echo "[3/3] Building polymorphic variant C"
./target/debug/jockey compile examples/process_triage.jy --output build/polymorph-c --polymorphic --cfg-flatten --encrypt-strings --junk-instructions --opaque-predicates >/tmp/jockey_poly_c.log 2>&1 || {
  echo "Build C failed" >&2
  cat /tmp/jockey_poly_c.log >&2
  exit 1
}
sha_c=$(find build/polymorph-c -type f -exec sha256sum {} + | sha256sum | cut -d' ' -f1)

if [ "$sha_a" = "$sha_b" ] || [ "$sha_b" = "$sha_c" ] || [ "$sha_a" = "$sha_c" ]; then
  echo "Polymorphic build verification failed: hashes were not unique" >&2
  echo "A=$sha_a" >&2
  echo "B=$sha_b" >&2
  echo "C=$sha_c" >&2
  exit 1
fi

echo "Polymorphic build verification passed"
echo "A=$sha_a"
echo "B=$sha_b"
echo "C=$sha_c"
