# `buzz-backend-box`

ASCII Box provider for Buzz managed remote agents. The provider implements the
same one-request/one-response protocol as `buzz-backend-kubernetes` and is
packaged as the `buzz-backend-box` desktop sidecar on supported macOS and Linux
hosts.

## Build and inspect

Activate the repository toolchain before building:

```bash
. ./bin/activate-hermit
cargo build -p buzz-backend-box --all-targets
```

Inspect provider discovery metadata without substrate credentials:

```bash
printf '%s\n' '{"op":"info","request_id":"local-check"}' \
  | ./target/debug/buzz-backend-box
```

A deploy request is normally produced by Buzz Desktop. If invoking it directly,
keep the private key in an inherited environment variable or a protected input
file. Do not put a real key in shell history, `provider_config`, or this
README:

```bash
export BUZZ_TEST_NSEC='<nsec supplied through a protected environment>'
printf '%s\n' '{"op":"deploy","request_id":"local-check","agent":{"private_key_nsec":"'"$BUZZ_TEST_NSEC"'","relay_url":"wss://relay.example.invalid"},"provider_config":{"machine_type":"small","workspace_mode":"persistent"}}' \
  | ./target/debug/buzz-backend-box
```

The provider itself resolves the Box credential from `BOX_API_KEY`, then falls
back to the Box CLI credential file at
`~/.config/ascii/box/config.json`. Provider configuration is non-secret and
supports `machine_type`, immutable `image`, `inactivity_seconds`, `scope`, and
`workspace_mode`.

On macOS, a GUI-launched Desktop process does not inherit a login-shell export
automatically. Provision `BOX_API_KEY` through the GUI launch environment or
use the CLI credential fallback, and make any helper binaries available on the
provider's effective `PATH`.

Relay presence is the only managed-agent status signal in protocol v1. Box
`ready`, `idle`, and `running` states do not prove that the Buzz harness is
online. Protocol v1 has no remote `status`, `logs`, or `undeploy` operation.
Use relay presence and substrate-side diagnostics instead.

Box stop means archive, not deletion. The public API has no supported hard
delete, and archived snapshots plus persistent workspace data can remain in the
account. Treat archive as retained data and billing/account-lifecycle state,
not secure erasure. ASCII currently documents EU-only regions (Germany,
Finland, and France), while SOC 2 remains in progress.

## Gated live validation spike

The spike is compiled as `box-live-spike`, but it is not part of provider
invocation or release execution. Safe local commands are:

```bash
cargo build -p buzz-backend-box --bin box-live-spike
./target/debug/box-live-spike --help
./target/debug/box-live-spike --dry-run all
```

A live group requires **both** an ambient `BOX_API_KEY` and the explicit
`--confirm-live` flag. The spike uses the API key only, not CLI credential
fallback, so operators can see exactly which credential authorizes a paid
account operation:

```bash
export BOX_API_KEY='<Box API key inherited from a protected environment>'
./target/debug/box-live-spike --confirm-live limits
```

The mutation groups are `no-env-self-stop`, `subdomain-race`,
`file-mode-output-caps`, `docker-snapshot-resume`, `network`, and `all`, plus
the read-only `limits` group. Every live result is structured JSON with check
status, HTTP status/error code when available, Box IDs, timings, and explicit
`manual_check_required` records for behaviors that cannot be safely inferred.
Candidates are stopped/archived where possible. The spike never force-stops or
hard-deletes Boxes. Do not run a mutating group unless spending a Box account's
resources is explicitly approved. `Restart=no` is intentional for the Box
systemd unit because ACP exit codes do not safely distinguish intentional
shutdown from failure (I5); an explicit Desktop Start is required to reconcile
an archived candidate. The spike has not been run against a real account in
this source change, so platform-dependent results remain unverified.

Exit codes are stable: `0` completed or dry-run, `2` usage error, `3` safety
gate blocked before network I/O, and `4` completed with at least one failed
check. The live spike has not been run against a real account in this source
change, so platform-dependent results remain unverified.

## Packaging

`just sidecar-list-check` verifies that the Box and Kubernetes provider names
remain present in the desktop Tauri, Justfile, bundle, CI, release, and canary
surfaces. Box is intentionally not added to mobile packaging.
