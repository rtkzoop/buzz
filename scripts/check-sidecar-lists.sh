#!/usr/bin/env bash
# Keep the Box and Kubernetes provider sidecars in every supported desktop
# packaging surface. This is intentionally a focused presence check, not a
# brittle snapshot of the surrounding build scripts.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

required_files=(
  Justfile
  scripts/bundle-sidecars.sh
  desktop/src-tauri/tauri.conf.json
  .github/workflows/ci.yml
  .github/workflows/release.yml
  .github/workflows/linux-canary.yml
  .github/workflows/macos-intel-canary.yml
  .github/workflows/signed-macos-canary.yml
)

for file in "${required_files[@]}"; do
  for provider in buzz-backend-kubernetes buzz-backend-box; do
    if ! grep -F -- "$provider" "$file" >/dev/null; then
      echo "missing $provider from $file" >&2
      exit 1
    fi
  done
done

if ! grep -F -- '"crates/buzz-backend-box"' Cargo.toml >/dev/null; then
  echo "workspace manifest does not register buzz-backend-box" >&2
  exit 1
fi
if ! grep -F -- 'name = "buzz-backend-box"' crates/buzz-backend-box/Cargo.toml >/dev/null; then
  echo "Box provider manifest is missing its package name" >&2
  exit 1
fi

check_paired_build_lines() {
  local file=$1
  while IFS= read -r line; do
    if [[ "$line" == *"cargo build"* && "$line" == *"buzz-backend-kubernetes"* && "$line" != *"buzz-backend-box"* ]]; then
      echo "Kubernetes build line omits Box in $file: $line" >&2
      return 1
    fi
  done < "$file"
}

for file in Justfile .github/workflows/ci.yml .github/workflows/release.yml \
  .github/workflows/linux-canary.yml .github/workflows/macos-intel-canary.yml \
  .github/workflows/signed-macos-canary.yml; do
  check_paired_build_lines "$file"
done

if ! grep -F -- 'SIDECARS+=(buzz-backend-kubernetes buzz-backend-box)' Justfile >/dev/null; then
  echo "Justfile sidecar stub list is missing the paired remote providers" >&2
  exit 1
fi
if ! grep -F -- 'STAGING_SIDECARS+=(buzz-backend-kubernetes buzz-backend-box)' Justfile >/dev/null; then
  echo "Justfile staging sidecar list is missing the paired remote providers" >&2
  exit 1
fi
if ! grep -F -- 'PRODUCTION_SIDECARS+=(buzz-backend-kubernetes buzz-backend-box)' Justfile >/dev/null; then
  echo "Justfile production sidecar list is missing the paired remote providers" >&2
  exit 1
fi
if ! grep -F -- 'for bin in buzz-acp buzz-agent buzz-backend-kubernetes buzz-backend-box' Justfile >/dev/null; then
  echo "Justfile standalone sidecar copy list is missing Box" >&2
  exit 1
fi
if ! grep -F -- 'SIDECARS+=(buzz-backend-kubernetes buzz-backend-box)' scripts/bundle-sidecars.sh >/dev/null; then
  echo "bundle-sidecars.sh does not stage the paired remote providers" >&2
  exit 1
fi
if ! grep -F -- 'buzz-backend-kubernetes -p buzz-backend-box' scripts/bundle-sidecars.sh >/dev/null; then
  echo "bundle-sidecars.sh build hint does not build Box" >&2
  exit 1
fi
if ! grep -F -- 'binaries/buzz-backend-kubernetes' desktop/src-tauri/tauri.conf.json >/dev/null \
  || ! grep -F -- 'binaries/buzz-backend-box' desktop/src-tauri/tauri.conf.json >/dev/null; then
  echo "Tauri externalBin list is missing a remote provider" >&2
  exit 1
fi

if grep -R -F -- "buzz-backend-box" mobile/ pubspec.yaml 2>/dev/null; then
  echo "Box provider must not be added to mobile packaging" >&2
  exit 1
fi

echo "Remote provider sidecar lists include Kubernetes and Box on supported desktop surfaces"
