# Oh My Pi Harness Selector Code Review

**Date:** 2026-07-30
**Review range:** `e1ed72c6..fc3b4694`
**Reviewer model:** gpt-5.5
**Verdict:** Clean after two correction rounds

## Findings resolved

1. **Standalone agents could retain a stale provider when switching to Oh My Pi.** Native metadata hid provider selection, but `resolveRuntimeProviderCapability("ompl", false)` returned `unknown`, causing submit to omit the provider update. Commit `7bfcc2bc` classifies `ompl` as provider-locked, emits an explicit `null` only when clearing an existing standalone provider, and preserves omit behavior for unknown/custom and linked instances. Unit regressions captured RED (`unknown` vs `locked`) and GREEN.
2. **The first Playwright provider assertion was a false positive.** The E2E bridge ignored provider seed/update values, so the record began at `null`. Commit `fc3b4694` adds provider seed/update handling with omit-vs-null semantics and makes the scenario assert `anthropic` before Save and `null` after Save. The strengthened test failed RED with expected `anthropic`, received `null`, then passed GREEN.

## Final review

A fresh independent review found no remaining Critical or Important issues. It confirmed native discovery/defaults and metadata, alias-aware create/edit matching, standalone provider clearing, linked and unknown/custom safety, genuine E2E persistence, unavailable setup guidance, and the live selector-derived Oh My Pi ACP contract.

## Verification evidence

- Rust managed-agent discovery: 80 passed, 0 failed
- Desktop frontend suite: 3530 passed, 0 failed
- Strict Tauri clippy and Rust fmt: passed
- TypeScript and exact-file Biome: passed
- E2E build and targeted Playwright: 4 passed
- Six screenshot hashes were distinct
- Live Oh My Pi 17.2.0 authored the exact requested Buzz reply with root plus one matching reply
- Owned temporary process and scratch directory cleanup: confirmed
