# Bast Access to the GCP Buzz Agent VM

**Date:** 2026-08-04
**Status:** Approved

## Goal

Make the private `buzz-agent` Compute Engine VM in the `zoop-innovation` project easy to reach from this Mac through the installed Bast terminal SSH picker, without adding a public IP or weakening the existing IAP-only network boundary.

## Current State

- Bast `v0.7.1` is installed locally.
- Bast GCP sync is disabled.
- The active gcloud configuration uses account `ravitej@zoop.one` and project `zoop-innovation`.
- The current gcloud OAuth credentials require refreshing before live discovery or SSH verification.
- The VM is named `buzz-agent` in zone `asia-south1-a`.
- `buzz-agent` has no external IP. Its egress uses Cloud NAT.
- TCP port 22 is reachable only from Google IAP's `35.235.240.0/20` source range.
- The deployment already documents `gcloud compute ssh buzz-agent --zone=asia-south1-a --tunnel-through-iap --project=zoop-innovation` as the supported SSH path.

## Product Decisions

| Question | Decision |
|---|---|
| Scope | This Mac and the current human gcloud identity only |
| Bast integration | Native Bast GCP sync |
| Network path | IAP TCP forwarding to the VM's private address |
| Project discovery | Restrict Bast GCP sync to `zoop-innovation` |
| SSH implementation | Bast-generated OpenSSH config and the system `ssh` binary |
| Credentials | Existing human gcloud OAuth identity and local OpenSSH key material |
| Infrastructure changes | None unless verification proves an existing IAM grant is missing |
| Public IP | Prohibited |
| Shared service-account key | Prohibited |
| Bast vault | Not required |

## Architecture

```text
Bast host picker or `bast connect <generated-alias>`
  -> ~/.ssh/bast/sync/gcp/config
  -> system OpenSSH client
  -> gcloud compute start-iap-tunnel
  -> Google IAP TCP forwarding
  -> 35.235.240.0/20 to buzz-agent:22
  -> private buzz-agent VM
```

Bast uses the local `gcloud` CLI for account discovery, Compute Engine listing, SSH preparation, and IAP tunneling. Because `buzz-agent` has no external IP, Bast must generate an IAP-backed `ProxyCommand`. Bast remains a picker and configuration generator; OpenSSH and gcloud remain the connection and authorization authorities.

No Buzz application code, Terraform resource, VM metadata, VPC firewall rule, DNS record, or external load-balancer resource changes as part of the normal setup.

## Setup Flow

1. Refresh the existing human account with `gcloud auth login ravitej@zoop.one`.
2. Confirm the active gcloud project is `zoop-innovation` and the account can list `buzz-agent`.
3. Prove the underlying access path before involving Bast by running an IAP-backed `gcloud compute ssh` command against `buzz-agent` in `asia-south1-a` and observing the remote hostname and user.
4. Open Bast's Sync tab, select GCP, set the project filter to `zoop-innovation`, and connect or sync the provider.
5. Allow Bast to reuse a matching local SSH key. If none is authorized, allow the same `~/.ssh/google_compute_engine` preparation used by `gcloud compute ssh`.
6. Set Bast's GCP default SSH user only if the synced host reports an unknown user; otherwise retain the user inferred from Compute metadata or OS Login.
7. Identify the generated SSH alias from `bast sync gcp --json` or the Bast detail pane. Do not assume its spelling.
8. Connect from the Bast picker and, separately, through `bast connect <generated-alias>`.

## Local State

Bast owns the generated GCP host entry under:

```text
~/.ssh/bast/sync/gcp/config
```

Bast adds the corresponding `Include` to its managed OpenSSH configuration. The generated GCP entries remain read-only and provider-owned. Project, zone, address, and IAP settings are refreshed by GCP sync rather than edited by hand.

The user's existing `~/.ssh/config` entries remain unchanged. In particular, this design does not add a second hand-maintained `Host buzz-agent` entry beside Bast's generated entry.

## Authorization and Security

The preferred path uses the user's own gcloud OAuth identity. It does not create, download, or store a service-account JSON key. SSH private keys remain local and are never copied into the repository, Terraform variables, Bast metadata, or the VM startup script.

If authorization is incomplete, grant only the missing capability to the human identity:

- Compute project and instance visibility for discovery.
- IAP tunnel access for the private SSH path.
- The existing Compute metadata or OS Login permission required to publish the user's SSH public key.

Do not respond to authorization failures by adding an external IP, opening port 22 to the internet, broadening the firewall source range, or reusing the VM service account as a human login credential.

## Failure Handling

- **OAuth 401 or invalid credentials:** refresh `ravitej@zoop.one` with `gcloud auth login`, then repeat the manual gcloud baseline.
- **Project or instance not discovered:** verify the active gcloud account, project filter, and Compute visibility before changing Bast.
- **IAP tunnel 403:** verify IAP TCP forwarding permission for the human account. Keep the IAP-only firewall unchanged.
- **SSH key publication denied:** determine whether the VM uses project metadata or OS Login and grant the matching least-privilege authorization. Never copy a private key to GCP.
- **Unknown SSH user:** use the Bast GCP default SSH user only after the manual gcloud connection reveals the correct remote account.
- **Bast connection fails after manual gcloud succeeds:** inspect the generated host entry and compare its project, zone, user, identity file, and `ProxyCommand` with the proven gcloud path.
- **Stale discovery:** run `bast sync gcp` again. Auto-sync may remain disabled unless repeated VM changes make it useful.

## Verification

1. `gcloud compute instances list` returns the running `buzz-agent` in `asia-south1-a`.
2. The manual IAP-backed SSH baseline reaches the VM and reports the expected hostname and remote user.
3. `bast sync gcp --json` succeeds and includes the `zoop-innovation` `buzz-agent` host.
4. The generated OpenSSH host contains an IAP `ProxyCommand`, not a direct external address.
5. A connection selected in the Bast TUI reaches the same `buzz-agent` VM.
6. `bast connect <generated-alias>` also reaches the VM.
7. The Compute instance still has no external NAT IP after setup.
8. The VPC firewall still permits port 22 only from `35.235.240.0/20` to the `buzz-agent` target tag.

The smoke check should run non-secret commands such as `hostname`, `whoami`, and `systemctl is-active buzz-acp`. It must not print environment variables, secret values, private keys, or VM startup metadata.

## Rollback

Run `bast sync disable gcp`. Bast removes the generated GCP hosts and its related include while leaving existing hand-managed SSH hosts and local Google Compute SSH keys intact. No infrastructure rollback is necessary because the normal setup changes no GCP resources.

## Out of Scope

- Adding a public IP to `buzz-agent`.
- Adding a direct internet SSH firewall rule.
- Changing Terraform or the VM startup script.
- Enabling access for additional people or machines.
- Adding the relay VM or other GCP projects to the Bast project filter.
- Enabling Bast vault synchronization.
- Creating a service-account key for interactive SSH.
- Repairing the separate `buzz-acp` service bootstrap issue.

## Success Criteria

The work is complete when all of the following are true:

1. Bast shows `buzz-agent` under Google Cloud and `zoop-innovation`.
2. Selecting it in Bast opens a working SSH session through IAP.
3. The generated CLI alias works with `bast connect`.
4. No external IP or internet SSH rule exists for the VM.
5. No repository secret, service-account key, or manually duplicated SSH host entry is created.
6. Disabling Bast GCP sync cleanly removes the generated local host entry.

## References

- [Bast GCP sync](https://bast.sh/docs/features/gcp)
- [Google Cloud `gcloud compute ssh`](https://docs.cloud.google.com/sdk/gcloud/reference/compute/ssh)
- Terraform sources: `deploy/gcp/agent.tf`, `deploy/gcp/network.tf`, and `deploy/gcp/outputs.tf` in the GCP deployment worktree
