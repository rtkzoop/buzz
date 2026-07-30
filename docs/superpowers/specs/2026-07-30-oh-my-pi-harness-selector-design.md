# Oh My Pi Harness Selector in Buzz Desktop

**Date:** 2026-07-30
**Status:** Approved

## Goal

Add Oh My Pi as a first-class ACP runtime in Buzz Desktop so it is always visible in the agent harness catalog and selectable in agent create and edit flows. Buzz must automatically detect the user's installed Oh My Pi executable, launch it in ACP mode with the correct arguments, preserve existing custom-command behavior, and show actionable setup guidance when Oh My Pi is not installed.

## Current Behavior and Root Cause

The create and edit dialogs already render their harness options from the native ACP runtime catalog returned by `discoverAcpRuntimes`. The catalog currently defines Goose, Claude Code, Codex, and Buzz Agent, but it does not define Oh My Pi. Therefore:

- Oh My Pi cannot appear in the create-agent harness dropdown.
- An existing agent configured with an absolute `ompl` command is treated as a custom command instead of a known harness.
- Desktop runtime discovery and Doctor cannot report Oh My Pi installation state.
- Buzz does not know that Oh My Pi requires the `acp` subcommand.

The modal components do not need a separate synthetic option. The missing first-class native runtime entry is the source of the UI gap.

## Product Decisions

| Question | Decision |
|---|---|
| Catalog visibility | Always show Oh My Pi, including when it is not installed |
| Integration layer | Native first-class ACP runtime catalog entry |
| Display label | `Oh My Pi` |
| Runtime id | `ompl` |
| Executable candidates | Prefer `ompl`, fall back to official `omp` |
| ACP arguments | Default to exactly `acp` |
| Provider ownership | Harness-managed; do not require or expose a separate provider selection |
| Model ownership | Use harness defaults by default; allow ACP-native model configuration when available |
| Install guidance | Official `curl -fsSL https://omp.sh/install | sh` installer and Oh My Pi documentation |
| Custom commands | Preserve unchanged as an escape hatch |
| Existing absolute `ompl` agents | Recognize as Oh My Pi when edited |

## Architecture

### Native runtime catalog

Add a `KnownAcpRuntime` entry in `desktop/src-tauri/src/managed_agents/discovery.rs` with the following semantics:

- `id`: `ompl`
- `label`: `Oh My Pi`
- executable candidates: `ompl`, then `omp`
- official install command: `curl -fsSL https://omp.sh/install | sh`
- official documentation: `https://github.com/can1357/oh-my-pi`
- avatar: `https://raw.githubusercontent.com/can1357/oh-my-pi/main/assets/icon.svg`
- no separate ACP adapter requirement
- no injected MCP server requirement because Oh My Pi provides native tools and accepts client MCP servers through ACP
- config path: `~/.omp/agent/config.yml`
- config format: YAML
- `skill_dir`: `.omp/skills`, allowing Buzz's existing skill bridge to place the canonical `buzz-cli` skill in the project-scoped directory; Oh My Pi continues to discover user-authored skills from `~/.omp/agent/skills` natively
- native ACP session configuration enabled for model and thinking controls
- no required normalized provider or model fields because Oh My Pi can use its own configured defaults

The executable candidate order is intentional. The current local development setup provides `/Users/ravitejkumar/.local/bin/ompl`, while the official installation provides `omp`. When both exist, Buzz should select `ompl` so the user's development launcher remains authoritative. When only the official CLI exists, discovery should select `omp`.

### Command identity and argument normalization

Teach runtime command normalization that `ompl`, `omp`, and absolute paths ending in either executable name identify the same Oh My Pi runtime.

Extend default argument normalization so:

```text
ompl -> ["acp"]
omp  -> ["acp"]
```

An explicit non-empty argument list remains authoritative. Normalization must not add a second `acp` argument when one is already present.

### Existing data flow

No new frontend runtime registry is introduced. The existing flow remains authoritative:

```text
KnownAcpRuntime
  -> Tauri discoverAcpRuntimes
  -> useAcpRuntimesQuery
  -> AgentDefinitionDialog / AgentInstanceEditDialog / defaults / Doctor
  -> selected AcpRuntime.command + AcpRuntime.defaultArgs
  -> managed-agent create or update input
  -> buzz-acp launches resolved Oh My Pi command in ACP mode
```

Create-from-definition already passes the discovered `runtime.command` and `runtime.defaultArgs` to the managed-agent input. Instance edit already updates the command and arguments when a known runtime is selected. Those paths should work without modal-specific branches once the catalog entry exists.

## Desktop UI Behavior

### Create agent

The harness dropdown shows:

- `Oh My Pi` when either executable candidate is available.
- `Oh My Pi (not installed)` when neither candidate is available.

When another available default runtime exists, the existing create-mode policy may keep unavailable options disabled. The option must remain visible so users can discover the supported harness and follow setup guidance.

Selecting an available Oh My Pi runtime stores runtime id `ompl` on the definition. Starting an instance resolves the discovered executable path and supplies `agentArgs: ["acp"]`.

### Edit agent

The edit dialog recognizes all of the following as Oh My Pi:

- a discovered absolute `ompl` path
- a discovered absolute `omp` path
- the bare command `ompl`
- the bare command `omp`
- a record whose runtime id is `ompl`

Selecting Oh My Pi pins the resolved command and sets the runtime arguments to `acp`. Existing absolute `/.../ompl` records must display `Oh My Pi` instead of `Custom command` when the catalog loads.

### AI configuration

The default AI configuration mode displays that model and provider come from the Oh My Pi harness.

Oh My Pi advertises ACP session config options for model and thinking level. Buzz uses its existing ACP-native configuration surface to read and set those controls when the session reports them. No Oh My Pi-specific modal controls are added. Provider remains harness-managed because Oh My Pi model identifiers encode the provider and the harness owns provider authentication.

The selector feature does not introduce new credential inputs, API-key storage, or provider environment variables.

### Doctor and setup guidance

Doctor displays Oh My Pi with the same availability semantics as other known runtimes. When unavailable, it provides the official installer and documentation. Oh My Pi has no separate adapter, so it must not display `adapter missing` or request an npm ACP adapter.

## Failure Handling

- **Not installed:** Keep Oh My Pi visible with the `not installed` suffix and route the user to Settings > Agents for setup.
- **Executable removed after configuration:** Existing start-time runtime validation refuses to launch the agent and returns the standard actionable runtime-unavailable error. Buzz must not silently fall back to another harness.
- **Only `omp` installed:** Discovery selects `omp` and launches `omp acp`.
- **Both `ompl` and `omp` installed:** Discovery selects `ompl` and launches `ompl acp`.
- **Existing custom path:** Match by normalized executable basename when the path ends in `ompl` or `omp`; unrelated custom commands remain custom.
- **ACP initialization failure:** Surface the existing managed-agent launch error. Do not reinterpret protocol failures as installation failures.
- **Custom installations:** Users can continue to choose `Custom command` and enter an arbitrary executable path and arguments.

## Testing Strategy

### Rust unit tests

Add or extend tests for:

1. `known_acp_runtime("ompl")` resolves the Oh My Pi entry.
2. `known_acp_runtime("omp")` resolves the same entry.
3. Absolute Unix and Windows-style paths ending in `ompl`, `omp`, or platform executable suffixes resolve correctly.
4. `normalize_agent_args("ompl", [])` returns `["acp"]`.
5. `normalize_agent_args("omp", [])` returns `["acp"]`.
6. Existing `["acp"]` input remains a single argument.
7. Explicit non-default arguments are preserved.
8. Discovery prefers `ompl` when both executable candidates are present.
9. Discovery falls back to `omp` when `ompl` is absent.
10. Catalog metadata has no adapter install requirement and includes official install guidance.

### Frontend unit and component tests

Use the mocked runtime catalog to verify:

1. Create mode lists `Oh My Pi` when available.
2. Create mode lists `Oh My Pi (not installed)` when unavailable.
3. Edit mode recognizes an existing absolute `/.../ompl` command.
4. Edit mode recognizes an existing absolute `/.../omp` command.
5. Selecting Oh My Pi applies the resolved command and `acp` arguments.
6. Custom command remains available and unchanged.
7. Provider selection is not rendered for Oh My Pi because the harness manages provider choice.
8. Existing runtime sorting and default selection remain stable for Buzz Agent, Goose, Claude, and Codex.

### Desktop screenshot and E2E evidence

Capture focused desktop screenshots with the mock bridge showing:

1. The create-agent harness dropdown containing available `Oh My Pi`.
2. The edit-agent harness dropdown recognizing an existing Oh My Pi agent.
3. The unavailable label is validated by component coverage; it does not require a third screenshot.

Screenshots must use the repository's desktop screenshot or Playwright mock bridge path, wait for animations, use focused cropping, and have distinct hashes before posting.

### Local integration smoke

On the current development machine:

1. Refresh runtime discovery and verify it resolves `/Users/ravitejkumar/.local/bin/ompl` rather than the secondary `omp` installation.
2. Open create and edit flows and verify the visible label is `Oh My Pi`.
3. Select Oh My Pi and verify the safe persisted projection contains the resolved command and exactly `["acp"]`.
4. Start only the dedicated test agent and verify one deterministic Buzz reply through the real ACP harness.
5. Stop the test agent and confirm unrelated managed agents and relay/Desktop processes remain healthy.

Do not print credentials, tokens, private keys, or complete managed-agent records during verification.

## Files Expected to Change

The implementation plan should confirm exact test locations, but the expected production scope is:

- `desktop/src-tauri/src/managed_agents/discovery.rs`
- `desktop/src-tauri/src/managed_agents/discovery/runtime_metadata.rs` only if metadata tests or comments need extension
- relevant existing Rust discovery test files
- desktop mock runtime catalog data used by component or E2E tests
- focused frontend tests or screenshot specifications

No modal-specific production component change is expected unless tests expose an existing catalog-consumption bug.

## Out of Scope

- Replacing the runtime catalog with a user-defined preset system.
- Migrating unrelated managed agents to Oh My Pi.
- Modifying the local `ompl` wrapper or the Oh My Pi source repository.
- Creating or storing new provider credentials.
- Adding a separate Oh My Pi ACP adapter.
- Removing or restricting Custom command.
- Changing global default harness preference to Oh My Pi.
- Refactoring unrelated agent modal code.

## Success Criteria

The work is complete when all of the following are true:

1. Oh My Pi is always visible in the create and edit harness catalogs.
2. Available installations display `Oh My Pi`; absent installations display `Oh My Pi (not installed)`.
3. The current machine resolves the local `ompl` launcher before official `omp`.
4. Selecting Oh My Pi launches the resolved executable with exactly `acp`.
5. Existing absolute `ompl` and `omp` agent commands are recognized as Oh My Pi on edit.
6. Doctor provides official install guidance without adapter guidance.
7. Custom command behavior is unchanged.
8. Focused Rust and desktop tests pass.
9. Screenshots prove both create and edit modal behavior.
10. A deterministic live Buzz reply succeeds through the selected Oh My Pi harness without disrupting unrelated processes.
