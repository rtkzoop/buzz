# Oh My Pi Harness Selector Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Oh My Pi as a first-class Buzz Desktop ACP harness that is always discoverable, appears correctly in agent create/edit flows, persists the resolved command with `acp`, and launches successfully through ACP.

**Architecture:** Keep native runtime discovery as the single source of truth. Register `ompl` with ordered executable candidates `ompl`, then `omp`, and reuse the existing catalog flow for create, defaults, and Doctor. Add one shared frontend command matcher so the instance edit dialog can associate bare or absolute `ompl` and `omp` commands with the catalog entry without creating a second runtime registry.

**Tech Stack:** Rust/Tauri, React 19 and TypeScript, Node test runner with `tsx`, Playwright desktop E2E, Hermit and Just.

## Global Constraints

- Do not introduce a frontend-only runtime registry or synthetic modal option.
- Always include Oh My Pi in the native catalog, even when neither executable is installed.
- Use runtime id exactly `ompl` and label exactly `Oh My Pi`.
- Probe executable candidates in exactly this order: `ompl`, then `omp`.
- Default both commands to exactly `agentArgs: ["acp"]`; preserve every explicit non-empty argument list unchanged.
- Recognize bare and absolute paths ending in `ompl`, `omp`, `ompl.exe`, or `omp.exe` in instance edit.
- Preserve `Custom command` behavior unchanged.
- Keep provider harness-managed. Do not add provider credentials, provider environment variables, or Oh My Pi-specific modal controls.
- Use `skill_dir: Some(".omp/skills")`, config path `~/.omp/agent/config.yml`, config format `yaml`, official installer `curl -fsSL https://omp.sh/install | sh`, docs `https://github.com/can1357/oh-my-pi`, and avatar `https://raw.githubusercontent.com/can1357/oh-my-pi/main/assets/icon.svg`.
- Do not add an ACP adapter or `buzz-dev-mcp` requirement for Oh My Pi.
- Activate Hermit before Cargo, pnpm, Git, or hooks.
- Do not commit generated screenshots, logs, credentials, or local agent stores.

## File Map

- Modify `desktop/src-tauri/src/managed_agents/discovery.rs`: runtime entry, executable ordering, and default arguments.
- Modify `desktop/src-tauri/src/managed_agents/discovery/runtime_metadata.rs`: metadata contract test.
- Modify `desktop/src-tauri/src/managed_agents/discovery/tests.rs`: command identity, avatar, and argument tests.
- Create `desktop/src/features/agents/lib/runtimeCommandMatcher.ts`: catalog-to-command matching shared by instance edit.
- Create `desktop/src/features/agents/lib/runtimeCommandMatcher.test.mjs`: matcher regression tests.
- Modify `desktop/src/features/agents/ui/AgentInstanceEditDialog.tsx`: replace raw equality checks with the shared matcher.
- Modify `desktop/src/features/agents/lib/instanceInputForDefinition.test.mjs`: prove create/deploy input keeps the discovered command and `acp` arguments.
- Modify `desktop/src/testing/e2eBridge.ts`: allow a managed-agent seed to specify command, command override, and arguments for edit-path E2E.
- Create `desktop/tests/e2e/oh-my-pi-harness-selector.spec.ts`: create/edit visibility, unavailable state, persistence, and screenshots.
- Modify `desktop/playwright.config.ts` only if its smoke `testMatch` excludes the new spec filename.

---

### Task 1 [zap:native-runtime]: Register Oh My Pi and its ACP defaults

**Files:**
- Modify: `desktop/src-tauri/src/managed_agents/discovery.rs`
- Modify: `desktop/src-tauri/src/managed_agents/discovery/runtime_metadata.rs`
- Modify: `desktop/src-tauri/src/managed_agents/discovery/tests.rs`

**Interfaces:**
- Produces `known_acp_runtime_exact("ompl")` with primary command `ompl` and fallback `omp`.
- Produces `normalize_agent_args("ompl" | "omp" | absolute path, []) == ["acp"]`.
- Leaves explicit non-empty arguments authoritative.

- [ ] **Step 1: Write failing Rust tests**

Add metadata assertions in `runtime_metadata.rs` for the exact id, label, ordered commands, installer, docs, avatar, skill/config fields, no adapter/MCP command, no model/provider env vars, empty required normalized fields, and ACP-native config support.

Add discovery tests in `tests.rs` equivalent to:

```rust
#[test]
fn recognizes_oh_my_pi_commands_paths_and_avatar() {
    for command in [
        "ompl",
        "omp",
        "/Users/example/.local/bin/ompl",
        "/opt/homebrew/bin/omp",
        r"C:\\Tools\\ompl.exe",
        r"C:\\Tools\\omp.exe",
    ] {
        let runtime = super::known_acp_runtime(command).expect("Oh My Pi runtime");
        assert_eq!(runtime.id, "ompl");
        assert_eq!(managed_agent_avatar_url(command).as_deref(), Some(OH_MY_PI_AVATAR_URL));
    }
}

#[test]
fn normalizes_oh_my_pi_args_to_acp_without_overwriting_explicit_args() {
    assert_eq!(normalize_agent_args("ompl", vec![]), vec!["acp"]);
    assert_eq!(normalize_agent_args("omp", vec![]), vec!["acp"]);
    assert_eq!(
        normalize_agent_args("/Users/example/.local/bin/ompl", vec![]),
        vec!["acp"]
    );
    assert_eq!(normalize_agent_args("omp", vec!["acp".into()]), vec!["acp"]);
    assert_eq!(
        normalize_agent_args("ompl", vec!["serve".into(), "--debug".into()]),
        vec!["serve", "--debug"]
    );
}
```

Add or refactor a small resolver test using temporary executable files so the first command in `commands: &["ompl", "omp"]` wins when both are resolvable and `omp` is selected when `ompl` is absent. Use existing command-resolution test helpers rather than mutating the process-wide PATH concurrently.

- [ ] **Step 2: Run the new tests and confirm RED**

```bash
. ./bin/activate-hermit
cargo test --manifest-path desktop/src-tauri/Cargo.toml recognizes_oh_my_pi_commands_paths_and_avatar -- --nocapture
cargo test --manifest-path desktop/src-tauri/Cargo.toml normalizes_oh_my_pi_args_to_acp_without_overwriting_explicit_args -- --nocapture
cargo test --manifest-path desktop/src-tauri/Cargo.toml oh_my_pi_metadata_matches_approved_contract -- --nocapture
```

Expected: each new test fails because no `ompl` runtime exists and default args are absent.

- [ ] **Step 3: Add the minimal runtime implementation**

Add `OH_MY_PI_AVATAR_URL` and this `KnownAcpRuntime` entry before `buzz-agent`:

```rust
KnownAcpRuntime {
    id: "ompl",
    label: "Oh My Pi",
    commands: &["ompl", "omp"],
    aliases: &[],
    avatar_url: OH_MY_PI_AVATAR_URL,
    mcp_command: None,
    mcp_hooks: false,
    underlying_cli: None,
    cli_install_commands: &["curl -fsSL https://omp.sh/install | sh"],
    cli_install_commands_windows: &[],
    adapter_install_commands: &[],
    cli_install_instructions_url: "https://github.com/can1357/oh-my-pi",
    adapter_install_instructions_url: "",
    cli_install_hint: "Install Oh My Pi with the official installer.",
    adapter_install_hint: "",
    skill_dir: Some(".omp/skills"),
    supports_acp_model_switching: true,
    model_env_var: None,
    provider_env_var: None,
    provider_locked: true,
    default_env: &[],
    config_file_path: Some("~/.omp/agent/config.yml"),
    config_file_format: Some("yaml"),
    supports_acp_native_config: true,
    thinking_env_var: None,
    max_tokens_env_var: None,
    context_limit_env_var: None,
    required_normalized_fields: &[],
    login_hint: None,
    auth_probe_args: None,
},
```

Extend `default_agent_args` so normalized `ompl` and `omp` return `Some(vec!["acp".to_string()])`. Do not change the existing non-empty-argument early return in `normalize_agent_args`.

- [ ] **Step 4: Run focused and discovery tests GREEN**

```bash
. ./bin/activate-hermit
cargo test --manifest-path desktop/src-tauri/Cargo.toml recognizes_oh_my_pi -- --nocapture
cargo test --manifest-path desktop/src-tauri/Cargo.toml normalizes_oh_my_pi -- --nocapture
cargo test --manifest-path desktop/src-tauri/Cargo.toml oh_my_pi_metadata -- --nocapture
cargo test --manifest-path desktop/src-tauri/Cargo.toml managed_agents::discovery -- --nocapture
```

Expected: all pass and the resolver-order assertion reports `ompl` before `omp`.

- [ ] **Step 5: Commit Task 1**

```bash
. ./bin/activate-hermit
git add desktop/src-tauri/src/managed_agents/discovery.rs \
  desktop/src-tauri/src/managed_agents/discovery/runtime_metadata.rs \
  desktop/src-tauri/src/managed_agents/discovery/tests.rs
git commit -m "feat(desktop): register Oh My Pi ACP runtime"
```

---

### Task 2 [zap:modal-matching]: Recognize Oh My Pi in instance edit without a second registry

**Files:**
- Create: `desktop/src/features/agents/lib/runtimeCommandMatcher.ts`
- Create: `desktop/src/features/agents/lib/runtimeCommandMatcher.test.mjs`
- Modify: `desktop/src/features/agents/ui/AgentInstanceEditDialog.tsx`
- Modify: `desktop/src/features/agents/lib/instanceInputForDefinition.test.mjs`

**Interfaces:**
- Produces `findRuntimeForCommand(runtimes, command)` returning the matching catalog entry.
- Matching supports exact runtime id, exact resolved command/binary path, normalized basename equality, and the `ompl` runtime's `ompl`/`omp` aliases.
- Create/deploy input continues consuming `runtime.command` and `runtime.defaultArgs` unchanged.

- [ ] **Step 1: Write the failing frontend tests**

Create `runtimeCommandMatcher.test.mjs` with cases for:

```text
ompl runtime + "ompl"                         -> ompl
ompl runtime + "omp"                          -> ompl
ompl runtime + "/Users/example/bin/ompl"      -> ompl
ompl runtime + "/opt/homebrew/bin/omp"        -> ompl
ompl runtime + "C:\\Tools\\omp.exe"         -> ompl
ompl runtime + unrelated custom command        -> undefined
other runtime + its exact resolved command      -> that runtime
```

Add a test to `instanceInputForDefinition.test.mjs` that supplies an available `ompl` catalog entry with `command: "/Users/example/.local/bin/ompl"` and `defaultArgs: ["acp"]`, then asserts the resulting managed-agent create input contains that exact `agentCommand` and `agentArgs`.

- [ ] **Step 2: Run and confirm RED**

```bash
. ./bin/activate-hermit
cd desktop
pnpm exec tsx --test \
  src/features/agents/lib/runtimeCommandMatcher.test.mjs \
  src/features/agents/lib/instanceInputForDefinition.test.mjs
```

Expected: matcher test fails because the module/function does not exist; create-input test should either fail on the missing case or pass as a characterization proving the existing data flow.

- [ ] **Step 3: Implement the matcher and wire all edit lookup sites**

Implement a small pure helper that normalizes slashes, takes the final path component, lowercases it, and strips `.exe`. Keep the only alias-specific rule next to the catalog id check:

```ts
const identities = runtime.id === "ompl" ? ["ompl", "omp"] : [];
```

In `AgentInstanceEditDialog.tsx`, replace the duplicated raw command/id lookup in:

1. dialog-open state reset,
2. catalog-arrival re-derivation,
3. `originalRuntimeSupportsProvider`, and
4. `prospectiveRuntimeId` fallback

with `findRuntimeForCommand(runtimes, agent.agentCommand)` or the original opening command as appropriate. Do not change dropdown selection, command pinning, argument assignment, or custom-command submission logic.

- [ ] **Step 4: Run frontend tests and lint GREEN**

```bash
. ./bin/activate-hermit
cd desktop
pnpm exec tsx --test \
  src/features/agents/lib/runtimeCommandMatcher.test.mjs \
  src/features/agents/lib/instanceInputForDefinition.test.mjs
pnpm exec biome check \
  src/features/agents/lib/runtimeCommandMatcher.ts \
  src/features/agents/lib/runtimeCommandMatcher.test.mjs \
  src/features/agents/ui/AgentInstanceEditDialog.tsx \
  src/features/agents/lib/instanceInputForDefinition.test.mjs
```

Expected: all tests and Biome pass.

- [ ] **Step 5: Commit Task 2**

```bash
. ./bin/activate-hermit
git add desktop/src/features/agents/lib/runtimeCommandMatcher.ts \
  desktop/src/features/agents/lib/runtimeCommandMatcher.test.mjs \
  desktop/src/features/agents/ui/AgentInstanceEditDialog.tsx \
  desktop/src/features/agents/lib/instanceInputForDefinition.test.mjs
git commit -m "fix(desktop): recognize Oh My Pi commands in agent edit"
```

---

### Task 3 [zap:e2e]: Prove create, unavailable, edit, and persistence behavior in the real dialogs

**Files:**
- Modify: `desktop/src/testing/e2eBridge.ts`
- Create: `desktop/tests/e2e/oh-my-pi-harness-selector.spec.ts`
- Modify: `desktop/playwright.config.ts` only if required by `testMatch`.

**Interfaces:**
- Extends `MockManagedAgentSeed` with optional `agentCommand`, `agentCommandOverride`, and `agentArgs`, and maps those fields in `buildSeededManagedAgent`.
- Uses a test-local raw catalog entry rather than changing the bridge's global default catalog.

- [ ] **Step 1: Extend the mock seed minimally**

Add optional fields to `MockManagedAgentSeed` and use them in the built raw record:

```ts
agentCommand?: string;
agentCommandOverride?: string | null;
agentArgs?: string[];
```

Map them to `agent_command`, `agent_command_override`, and `agent_args`, preserving current defaults when omitted.

- [ ] **Step 2: Write the Playwright spec against existing helpers**

Import `installMockBridge` and `TEST_IDENTITIES` from `../helpers/bridge` and `waitForAnimations` from `../helpers/animations`. Define test-local available and unavailable `ompl` catalog entries.

Cover these behaviors:

1. Create from scratch, enter Customize, open `#persona-runtime`, and assert `Oh My Pi` is visible and selectable. After selection, assert the provider field is hidden and harness-default mode remains valid.
2. With unavailable `ompl` plus an available default runtime, open the same dropdown and assert `Oh My Pi (not installed)` remains visible. Verify setup guidance is reachable through the existing unavailable-runtime UI rather than expecting a URL string inside the menu.
3. Seed a standalone stopped agent with `agentCommand: "/Users/example/.local/bin/ompl"`, `agentCommandOverride` equal to that path, and `agentArgs: ["acp"]`. Open the Agents view, profile, and instance edit dialog. Assert `#edit-agent-runtime` displays `Oh My Pi`; expand Advanced and assert the arguments field contains `acp`.
4. In the edit test, switch to `Oh My Pi` from a bare `omp` seed, save, reopen, and assert the resolved catalog command and `acp` remain selected. This exercises the mock update mutation and persistence, not localStorage.

Before each screenshot, call `waitForAnimations(page)`. Save scoped dialog/menu screenshots under `test-results/oh-my-pi-harness-selector/`; do not commit them.

- [ ] **Step 3: Run the E2E spec and confirm GREEN**

```bash
. ./bin/activate-hermit
cd desktop
pnpm exec playwright test tests/e2e/oh-my-pi-harness-selector.spec.ts --project=smoke
shasum -a 256 test-results/oh-my-pi-harness-selector/*.png
```

Expected: all tests pass and every screenshot has a distinct hash.

- [ ] **Step 4: Run desktop type/lint checks**

```bash
. ./bin/activate-hermit
cd desktop
pnpm exec tsc --noEmit --pretty false
pnpm exec biome check src/testing/e2eBridge.ts tests/e2e/oh-my-pi-harness-selector.spec.ts
```

Expected: PASS.

- [ ] **Step 5: Commit Task 3 without generated PNGs**

```bash
. ./bin/activate-hermit
git add desktop/src/testing/e2eBridge.ts \
  desktop/tests/e2e/oh-my-pi-harness-selector.spec.ts \
  desktop/playwright.config.ts
git commit -m "test(desktop): cover Oh My Pi harness selection"
```

The smoke allowlist change is required. Do not stage generated screenshots.

---

### Task 4 [zap:live-verification]: Close the full discovery-to-ACP feedback loop

**Files:**
- Modify production or test files only when verification exposes a reproducible defect, and add a failing regression test before each fix.
- Do not commit local stores, credentials, generated logs, or screenshots.

**Interfaces:**
- Consumes the real detected `/Users/ravitejkumar/.local/bin/ompl` with official `omp` fallback.
- Produces evidence for catalog command selection, persisted `acp` arguments, and an exact deterministic ACP-authored Buzz reply.

- [ ] **Step 1: Run focused and project checks**

```bash
. ./bin/activate-hermit
cargo test --manifest-path desktop/src-tauri/Cargo.toml managed_agents::discovery -- --nocapture
cargo clippy --manifest-path desktop/src-tauri/Cargo.toml --all-targets -- -D warnings
cargo fmt --manifest-path desktop/src-tauri/Cargo.toml --all -- --check
cd desktop
pnpm exec tsx --test \
  src/features/agents/lib/runtimeCommandMatcher.test.mjs \
  src/features/agents/lib/instanceInputForDefinition.test.mjs
pnpm exec tsc --noEmit --pretty false
```

Expected: all pass without warnings.

- [ ] **Step 2: Verify actual executable discovery and ACP entrypoint**

```bash
command -v ompl
ompl --version
ompl acp --help
```

Expected on the current machine: `ompl` resolves before `omp`, version prints successfully, and ACP help identifies the stdio server. Temporarily test an isolated command-search fixture where only `omp` exists to prove fallback without changing the user's PATH or installation.

- [ ] **Step 3: Verify persisted managed-agent command and arguments**

Use the existing managed-agent create/update API or CLI test harness to create a temporary Oh My Pi-backed definition and instance. Re-read the stored definition and agent record and assert:

```text
runtime == "ompl"
agent command resolves to the discovered ompl path
agent args == ["acp"]
provider is unset/harness-managed
```

Clean up only the temporary definition/instance created for this verification. Preserve unrelated agents and processes.

- [ ] **Step 4: Run a deterministic live Buzz-to-Oh-My-Pi-to-Buzz reply**

Send a unique prompt requiring one exact token, wait for the agent-authored thread reply, and assert:

```text
reply content == expected token
reply author == temporary managed agent pubkey
thread contains the root and exactly one matching reply
```

Capture the root event id, reply event id, expected token, selected command, arguments, and latency. If a failure occurs, first add a failing automated regression test for the defect, then fix and rerun this step.

- [ ] **Step 5: Clean up and inspect ownership boundaries**

Stop/delete only the temporary agent and definition. Confirm no owned temporary process, harness directory, or test database remains. Confirm unrelated managed agents are unchanged.

- [ ] **Step 6: Commit verification fixes only if needed**

Stage explicit file paths for any tested fixes and commit with a focused message. If verification required no code changes, do not create an empty commit.

---

## Final Verification

- [ ] Rust discovery tests, full Tauri clippy, and Rust formatting pass.
- [ ] Frontend matcher/create-input tests, TypeScript, and Biome pass.
- [ ] Targeted Playwright create/edit/unavailable tests pass.
- [ ] Screenshot hashes are all distinct and screenshots are not committed.
- [ ] Live catalog discovery selects `ompl` first and proves `omp` fallback in isolation.
- [ ] Stored runtime, command, arguments, and provider ownership match the approved contract.
- [ ] A real Oh My Pi ACP process authors the exact deterministic Buzz reply.
- [ ] Temporary resources are removed without touching unrelated agents.
- [ ] The 2026-07-30 implementation plan is committed before Task 1, and final `git status --short` contains only the two unrelated pre-existing untracked 2026-07-28 documents.
