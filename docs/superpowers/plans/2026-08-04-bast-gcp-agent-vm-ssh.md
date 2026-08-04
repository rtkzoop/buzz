# Bast GCP Agent VM SSH Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Configure this Mac's Bast installation to discover and connect to the private `buzz-agent` VM in `zoop-innovation` through Google IAP.

**Architecture:** Bast uses the authenticated local gcloud CLI to discover the VM and writes a provider-owned OpenSSH host under `~/.ssh/bast/sync/gcp/config`. Because the VM has no external IP, the generated host routes system OpenSSH through `gcloud compute start-iap-tunnel`; GCP IAM and the existing IAP-only firewall remain authoritative.

**Tech Stack:** Bast `v0.7.1`, Google Cloud CLI, Compute Engine, Identity-Aware Proxy TCP forwarding, OpenSSH, macOS

## Global Constraints

- Scope is this Mac and the current human gcloud identity only.
- Project is exactly `zoop-innovation`; VM is exactly `buzz-agent`; zone is exactly `asia-south1-a`.
- Preserve the VM's private-only design: no external IP and no direct internet SSH firewall rule.
- Do not modify Buzz application code, Terraform, VM startup metadata, DNS, or load-balancer resources.
- Do not create or download a service-account JSON key.
- Do not enable Bast vault synchronization.
- Do not copy or print private keys, secret values, environment variables, or VM startup metadata.
- Let Bast and gcloud manage generated files; do not hand-edit generated GCP host blocks.
- The existing `buzz-acp` bootstrap issue is outside this plan and must not be treated as an SSH failure.

## File Structure

No repository production file changes are required. The implementation affects only tool-managed local state:

- Modify through `gcloud auth login`: `~/.config/gcloud/credentials.db`
- Create through Bast initialization: `~/.ssh/bast/config`
- Create through Bast GCP sync: `~/.ssh/bast/sync/gcp/config`
- Modify through Bast initialization: `~/.ssh/config` with one `Include ~/.ssh/bast/config` entry
- Modify through Bast settings: `~/.config/bast/state.json`
- Reuse, and register the public half when required: `~/.ssh/google_compute_engine` and `~/.ssh/google_compute_engine.pub`

The engineer must not edit `credentials.db`, `state.json`, generated SSH files, or private-key files directly.

---

### Task 1: Refresh gcloud and prove the IAP baseline

**Files:**
- Modify through gcloud: `~/.config/gcloud/credentials.db`
- Reuse: `~/.ssh/google_compute_engine`
- Reuse: `~/.ssh/google_compute_engine.pub`
- Verify infrastructure source: `.claude/worktrees/ompl-buzz-local/deploy/gcp/agent.tf`
- Verify infrastructure source: `.claude/worktrees/ompl-buzz-local/deploy/gcp/network.tf`

**Interfaces:**
- Consumes: Google identity `ravitej@zoop.one`, project `zoop-innovation`, VM `buzz-agent`, zone `asia-south1-a`
- Produces: a refreshed gcloud session and a proven private IAP SSH path that Bast can reuse

- [ ] **Step 1: Refresh the existing human gcloud login**

Run:

```bash
gcloud auth login ravitej@zoop.one
```

Expected: the browser-based OAuth flow completes, and gcloud reports `ravitej@zoop.one` as authenticated. Do not use `--cred-file`, application-default credentials, or a service-account key.

- [ ] **Step 2: Pin and verify the active account and project**

Run:

```bash
gcloud config set account ravitej@zoop.one
gcloud config set project zoop-innovation
gcloud auth list --filter=status:ACTIVE --format='value(account)'
gcloud config get-value project
```

Expected output:

```text
ravitej@zoop.one
zoop-innovation
```

Do not rely on the configured default Compute zone, which is currently `asia-south1-c`; every VM command in this plan supplies `--zone=asia-south1-a` explicitly.

- [ ] **Step 3: Verify that gcloud can discover the running VM**

Run:

```bash
gcloud compute instances describe buzz-agent \
  --project=zoop-innovation \
  --zone=asia-south1-a \
  --format='table(name,status,zone.basename(),networkInterfaces[0].networkIP)'
```

Expected: one row with name `buzz-agent`, status `RUNNING`, zone `asia-south1-a`, and a private `10.20.0.0/24` address.

If this returns an OAuth `401`, repeat Step 1. If it returns a Compute authorization `403`, verify that `ravitej@zoop.one` is the active account and has permission to view instances in `zoop-innovation`; do not change the VM or firewall.

- [ ] **Step 4: Confirm that the VM still has no external address**

Run:

```bash
gcloud compute instances describe buzz-agent \
  --project=zoop-innovation \
  --zone=asia-south1-a \
  --format='get(networkInterfaces[0].accessConfigs[0].natIP)'
```

Expected: empty output. Any public address is a security regression that must be investigated before continuing.

- [ ] **Step 5: Confirm the IAP-only firewall contract**

Run:

```bash
gcloud compute firewall-rules describe buzz-allow-iap-ssh \
  --project=zoop-innovation \
  --format='json(allowed,sourceRanges,targetTags)'
```

Expected JSON contains all three invariants:

```json
{
  "allowed": [
    {
      "IPProtocol": "tcp",
      "ports": ["22"]
    }
  ],
  "sourceRanges": ["35.235.240.0/20"],
  "targetTags": ["buzz-agent", "buzz-relay", "buzz-restore"]
}
```

Array ordering may differ; the values must not.

- [ ] **Step 6: Prove SSH independently of Bast**

Run:

```bash
gcloud compute ssh buzz-agent \
  --project=zoop-innovation \
  --zone=asia-south1-a \
  --tunnel-through-iap \
  --command='hostname; whoami'
```

Expected: the first line is `buzz-agent`; the second line is a non-empty, non-root Linux username. Record that username locally for comparison with Bast's generated `User`, but do not add a manual SSH host entry.

If the tunnel returns an IAP `403`, verify that `ravitej@zoop.one` has `roles/iap.tunnelResourceAccessor`. If SSH key publication is denied, determine whether the failure names Compute metadata or OS Login and grant the matching human-user authorization; never work around either failure with a public IP or copied private key.

---

### Task 2: Enable project-scoped Bast GCP sync

**Files:**
- Create through Bast: `~/.ssh/bast/config`
- Create through Bast: `~/.ssh/bast/sync/gcp/config`
- Modify through Bast: `~/.ssh/config`
- Modify through Bast: `~/.config/bast/state.json`

**Interfaces:**
- Consumes: the working gcloud session and IAP baseline from Task 1
- Produces: a read-only Bast-synced `buzz-agent` host and a generated OpenSSH alias

- [ ] **Step 1: Confirm the pre-change Bast state**

Run:

```bash
bast --version
bast sync status --json
```

Expected: version `bast v0.7.1`; GCP reports `"enabled": false`; the account list includes `ravitej@zoop.one`.

- [ ] **Step 2: Configure GCP sync in the Bast TUI**

Run:

```bash
bast
```

In the TUI:

1. Press `3` to open **Sync**.
2. Select **GCP**.
3. Set **Project filter** to exactly `zoop-innovation`.
4. Leave auto-sync disabled; manual sync is sufficient for a stable VM.
5. Choose **Connect** or **Sync now**.
6. Return to the host picker and locate `buzz-agent` under **Google Cloud / zoop-innovation**.

Expected: Bast completes discovery without a cloud-agent installation, service-account key, or request to add a public address.

- [ ] **Step 3: Verify provider state through the CLI**

Run:

```bash
bast sync status --json
bast sync gcp --json
```

Expected: GCP reports `"enabled": true`; the sync command returns `"ok": true` and discovers the running `buzz-agent` in `zoop-innovation`. Stopped VMs and other projects must not appear in the generated GCP group.

- [ ] **Step 4: Resolve the generated alias without assuming its spelling**

Run:

```bash
BAST_ALIAS="$(bast hosts list --json | jq -r '.data[] | select(.synced == true and .label == "buzz-agent") | .alias')"
printf '%s\n' "$BAST_ALIAS"
test -n "$BAST_ALIAS"
```

Expected: exactly one non-empty alias is printed and `test` exits `0`. If more than one line is returned, re-check that the Bast project filter is exactly `zoop-innovation` before continuing.

- [ ] **Step 5: Verify Bast's generated OpenSSH include chain**

Inspect these files without editing them:

```text
~/.ssh/config
~/.ssh/bast/config
~/.ssh/bast/sync/gcp/config
```

Expected:

- `~/.ssh/config` includes `~/.ssh/bast/config` once.
- `~/.ssh/bast/config` includes `~/.ssh/bast/sync/gcp/config` once.
- The GCP config has one provider-owned host for `buzz-agent`.
- The host names project `zoop-innovation` and zone `asia-south1-a` in its gcloud command.
- The host uses `gcloud compute start-iap-tunnel`; it does not contain a public IP.
- The `User` matches the successful Task 1 connection. If Bast reports the user as unknown, set **Default SSH user** in the GCP submenu to that exact Task 1 username, re-run `bast sync gcp`, and inspect again.

- [ ] **Step 6: Verify the effective OpenSSH route**

Run in the same shell where `BAST_ALIAS` was assigned:

```bash
ssh -G "$BAST_ALIAS" | sed -n 's/^proxycommand /proxycommand /p'
```

Expected: one `proxycommand` line containing all of:

```text
gcloud compute start-iap-tunnel
buzz-agent
asia-south1-a
zoop-innovation
```

The command may contain additional gcloud flags. It must not resolve to direct port 22 on a public address.

---

### Task 3: Exercise Bast access and prove safe rollback

**Files:**
- Verify: `~/.ssh/bast/config`
- Verify: `~/.ssh/bast/sync/gcp/config`
- Verify: `~/.config/bast/state.json`

**Interfaces:**
- Consumes: the generated `BAST_ALIAS` and synced host from Task 2
- Produces: verified picker and CLI access, a tested rollback path, and the final enabled GCP sync state

- [ ] **Step 1: Connect through the Bast CLI alias**

If this is a new shell, reconstruct the alias:

```bash
BAST_ALIAS="$(bast hosts list --json | jq -r '.data[] | select(.synced == true and .label == "buzz-agent") | .alias')"
test -n "$BAST_ALIAS"
bast connect "$BAST_ALIAS"
```

At the remote prompt, run:

```bash
hostname
whoami
exit
```

Expected: `hostname` prints `buzz-agent`; `whoami` matches Task 1; `exit` returns to the local shell. Bast's connection status must show GCP/IAP preparation rather than a direct public connection.

- [ ] **Step 2: Connect from the Bast picker**

Run:

```bash
bast
```

Search for `buzz-agent`, select the host under **Google Cloud / zoop-innovation**, and press Enter. At the remote prompt run `hostname`, then `exit`.

Expected: `hostname` prints `buzz-agent`, proving the intended picker workflow works end to end.

- [ ] **Step 3: Re-check the network boundary after successful access**

Run:

```bash
gcloud compute instances describe buzz-agent \
  --project=zoop-innovation \
  --zone=asia-south1-a \
  --format='get(networkInterfaces[0].accessConfigs[0].natIP)'

gcloud compute firewall-rules describe buzz-allow-iap-ssh \
  --project=zoop-innovation \
  --format='json(allowed,sourceRanges,targetTags)'
```

Expected: the first command prints nothing; the second still permits only TCP 22 from `35.235.240.0/20` to tags including `buzz-agent`.

- [ ] **Step 4: Rehearse the local rollback**

Run:

```bash
bast sync disable gcp
bast sync status --json
test ! -e "$HOME/.ssh/bast/sync/gcp/config"
```

Expected: GCP reports `"enabled": false`; the generated GCP config is absent; the hand-managed `innovation` and `github.com` hosts remain visible in `bast hosts list --json`. `~/.ssh/google_compute_engine` remains intact.

- [ ] **Step 5: Restore the intended final state**

Run:

```bash
bast sync gcp --json
bast sync status --json
```

Expected: the saved `zoop-innovation` project filter is reused; GCP reports `"enabled": true`; `~/.ssh/bast/sync/gcp/config` is recreated; `buzz-agent` is rediscovered.

Reconstruct the alias and run one final connection:

```bash
BAST_ALIAS="$(bast hosts list --json | jq -r '.data[] | select(.synced == true and .label == "buzz-agent") | .alias')"
test -n "$BAST_ALIAS"
bast connect "$BAST_ALIAS"
```

At the remote prompt, run `hostname` and `exit`. Expected: `buzz-agent`, followed by a clean return to the local shell.

- [ ] **Step 6: Record final evidence without secrets**

Record only:

- Bast version.
- Generated alias.
- Successful manual gcloud IAP baseline.
- Successful Bast CLI connection.
- Successful Bast picker connection.
- Empty external-IP query.
- IAP-only firewall source range.
- Successful disable-and-restore rehearsal.

Do not record OAuth tokens, private-key contents, Secret Manager values, environment variables, startup metadata, or the full contents of gcloud credential databases.

No implementation commit is required: the deliverable is local tool-managed state, and no repository production file changes are permitted by this plan.

## References

- Approved design: `docs/superpowers/specs/2026-08-04-bast-gcp-agent-vm-ssh-design.md`
- [Bast GCP sync](https://bast.sh/docs/features/gcp)
- [Bast files and storage](https://bast.sh/docs/reference/files)
- [Google Cloud `gcloud compute ssh`](https://docs.cloud.google.com/sdk/gcloud/reference/compute/ssh)
