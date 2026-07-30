import { execFile } from "node:child_process";
import { promisify } from "node:util";

import { expect, test } from "@playwright/test";

import { TwoRelayHarness, type RelaySpec } from "./helpers/twoRelayHarness";

const exec = promisify(execFile);
const enabled = process.env.BUZZ_E2E_AGENTS_EVERYWHERE === "1";
const relayBin = process.env.BUZZ_E2E_RELAY_BIN;
const cliBin = process.env.BUZZ_E2E_CLI_BIN;
const adminBin = process.env.BUZZ_E2E_ADMIN_BIN;
const lazyPoolSize = 24;
const fakeAcpWakeDelayMs = 500;
// Serial initialization takes at least 12s with this fixture. First-ready lazy
// wake should comfortably publish its reply below this bound on CI.
const maxLazyWakeMs = 8_000;
// ACP subscriptions intentionally replay a five-second startup skew window.
// Age the initial probe beyond it so restart begins genuinely idle.
const startupReplaySkewClearMs = 6_000;

function required(name: string, value: string | undefined): string {
  if (!value) throw new Error(`${name} is required for the live gate`);
  return value;
}

async function run(
  binary: string,
  args: string[],
  env: NodeJS.ProcessEnv = {},
): Promise<string> {
  const { stdout } = await exec(binary, args, {
    cwd: "..",
    env: { ...process.env, BUZZ_AUTH_TAG: "", ...env },
  });
  return stdout;
}

function keyField(output: string, label: string): string {
  const value = output.match(new RegExp(`^${label}:\\s+(\\S+)$`, "m"))?.[1];
  if (!value) throw new Error(`missing ${label} in key output`);
  return value;
}

async function processTree(
  rootPid: number,
): Promise<Array<{ pid: number; rssKb: number; command: string }>> {
  const { stdout } = await exec("ps", ["-axo", "pid=,ppid=,rss=,command="]);
  const rows = stdout
    .trim()
    .split("\n")
    .map((line) => {
      const match = line.trim().match(/^(\d+)\s+(\d+)\s+(\d+)\s+(.*)$/);
      if (!match) return undefined;
      return {
        pid: Number(match[1]),
        ppid: Number(match[2]),
        rssKb: Number(match[3]),
        command: match[4],
      };
    })
    .filter((row): row is NonNullable<typeof row> => row !== undefined);
  const pids = new Set([rootPid]);
  let changed = true;
  while (changed) {
    changed = false;
    for (const row of rows) {
      if (pids.has(row.ppid) && !pids.has(row.pid)) {
        pids.add(row.pid);
        changed = true;
      }
    }
  }
  return rows
    .filter((row) => pids.has(row.pid))
    .map(({ pid, rssKb, command }) => ({ pid, rssKb, command }));
}

async function eventually<T>(fn: () => Promise<T | undefined>): Promise<T> {
  const deadline = Date.now() + 30_000;
  let lastError: unknown;
  while (Date.now() < deadline) {
    try {
      const value = await fn();
      if (value !== undefined) return value;
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  throw lastError ?? new Error("live assertion timed out");
}

async function sendAndAwaitAck(
  relay: RelaySpec,
  channelId: string,
  senderKey: string,
  probe: string,
): Promise<number> {
  const relayHttp = `http://127.0.0.1:${relay.ports.main}`;
  const wakeStartedAt = Date.now();
  await run(
    required("BUZZ_E2E_CLI_BIN", cliBin),
    [
      "messages",
      "send",
      "--channel",
      channelId,
      "--content",
      `@AgentsEverywhereProbe AE-ID:${probe}`,
    ],
    { BUZZ_RELAY_URL: relayHttp, BUZZ_PRIVATE_KEY: senderKey },
  );
  const expectedAck = `AE-ACK:${probe}`;
  const messages = await eventually(async () => {
    const output = await run(
      required("BUZZ_E2E_CLI_BIN", cliBin),
      ["messages", "get", "--channel", channelId, "--limit", "20"],
      { BUZZ_RELAY_URL: relayHttp, BUZZ_PRIVATE_KEY: senderKey },
    );
    const rows = JSON.parse(output) as Array<{ content?: string }>;
    return rows.some((row) => row.content === expectedAck) ? rows : undefined;
  });
  expect(messages.filter((row) => row.content === expectedAck)).toHaveLength(1);
  const latencyMs = Date.now() - wakeStartedAt;
  expect(latencyMs).toBeLessThan(maxLazyWakeMs);
  return latencyMs;
}

test.describe("agents everywhere live two-relay gate", () => {
  test.skip(!enabled, "set BUZZ_E2E_AGENTS_EVERYWHERE=1 to run live gate");

  test("same agent listens and wakes independently in two communities", async () => {
    test.setTimeout(90_000);
    const portBase = 20_000 + (process.pid % 5_000) * 2;
    const specs: [RelaySpec, RelaySpec] = [
      {
        name: "relay-a",
        ports: {
          main: portBase,
          health: portBase + 10_000,
          metrics: portBase + 20_000,
        },
        databaseUrl: required(
          "BUZZ_E2E_DATABASE_URL",
          process.env.BUZZ_E2E_DATABASE_URL,
        ),
        redisUrl: process.env.BUZZ_E2E_REDIS_A ?? "redis://127.0.0.1:6379/11",
      },
      {
        name: "relay-b",
        ports: {
          main: portBase + 1,
          health: portBase + 10_001,
          metrics: portBase + 20_001,
        },
        databaseUrl: required(
          "BUZZ_E2E_DATABASE_URL",
          process.env.BUZZ_E2E_DATABASE_URL,
        ),
        redisUrl: process.env.BUZZ_E2E_REDIS_B ?? "redis://127.0.0.1:6379/12",
      },
    ];
    const harness = await TwoRelayHarness.create(specs);
    try {
      await harness.startRelays(required("BUZZ_E2E_RELAY_BIN", relayBin));
      const senderOutput = await run(required("BUZZ_E2E_ADMIN_BIN", adminBin), [
        "generate-key",
      ]);
      const agentOutput = await run(required("BUZZ_E2E_ADMIN_BIN", adminBin), [
        "generate-key",
      ]);
      const senderKey = keyField(senderOutput, "Secret key");
      const agentKey = keyField(agentOutput, "Secret key");
      const agentPubkey = keyField(agentOutput, "Public key");
      const channels: Array<{ relay: RelaySpec; id: string }> = [];

      for (const relay of specs) {
        const relayHttp = `http://127.0.0.1:${relay.ports.main}`;
        const senderEnv = {
          BUZZ_RELAY_URL: relayHttp,
          BUZZ_PRIVATE_KEY: senderKey,
        };
        const created = JSON.parse(
          await run(
            required("BUZZ_E2E_CLI_BIN", cliBin),
            [
              "channels",
              "create",
              "--name",
              `ae-live-${relay.name}-${process.pid}`,
              "--type",
              "stream",
              "--visibility",
              "open",
            ],
            senderEnv,
          ),
        );
        await run(
          required("BUZZ_E2E_CLI_BIN", cliBin),
          [
            "channels",
            "add-member",
            "--channel",
            created.channel_id,
            "--pubkey",
            agentPubkey,
            "--role",
            "member",
          ],
          senderEnv,
        );
        await run(
          required("BUZZ_E2E_CLI_BIN", cliBin),
          ["users", "set-profile", "--name", "AgentsEverywhereProbe"],
          { BUZZ_RELAY_URL: relayHttp, BUZZ_PRIVATE_KEY: agentKey },
        );
        channels.push({ relay, id: created.channel_id });
      }

      const acpChildren = [];
      const acpEnv = {
        BUZZ_ACP_AGENTS: String(lazyPoolSize),
        BUZZ_ACP_RESPOND_TO: "anyone",
        BUZZ_ACP_NO_MEMORY: "true",
        BUZZ_E2E_FAKE_ACP_WAKE_MS: String(fakeAcpWakeDelayMs),
      };
      for (const { relay } of channels) {
        acpChildren.push(
          await harness.startAcp(
            `acp-${relay.name}`,
            `ws://127.0.0.1:${relay.ports.main}`,
            agentKey,
            acpEnv,
          ),
        );
      }
      await new Promise((resolve) => setTimeout(resolve, 2_000));
      if (!acpChildren.every((child) => child.exitCode === null)) {
        throw new Error(`ACP listener exited early:\n${await harness.logs()}`);
      }
      const idleTrees = await Promise.all(
        acpChildren.map((child) => {
          if (!child.pid) throw new Error("ACP listener has no pid");
          return processTree(child.pid);
        }),
      );
      expect(idleTrees.every((tree) => tree.length === 1)).toBe(true);
      test.info().annotations.push({
        type: "idle-processes",
        description: idleTrees
          .map(
            (tree) =>
              `${tree.length} process / ${tree.reduce((sum, row) => sum + row.rssKb, 0)} KiB RSS`,
          )
          .join("; "),
      });

      const initialLatencies = [];
      for (const { relay, id } of channels) {
        initialLatencies.push({
          relay: relay.name,
          latencyMs: await sendAndAwaitAck(
            relay,
            id,
            senderKey,
            `${relay.name}-initial`,
          ),
        });
      }

      const refilledTrees = await eventually(async () => {
        const trees = await Promise.all(
          acpChildren.map((child) => {
            if (!child.pid) throw new Error("ACP listener has no pid");
            return processTree(child.pid);
          }),
        );
        return trees.every((tree) => tree.length > 1) ? trees : undefined;
      });
      expect(refilledTrees.every((tree) => tree.length > 1)).toBe(true);

      const restarted = channels[0];
      await harness.terminateProcessGracefully(`acp-${restarted.relay.name}`);
      await new Promise((resolve) =>
        setTimeout(resolve, startupReplaySkewClearMs),
      );
      const restartedAcp = await harness.startAcp(
        `acp-${restarted.relay.name}`,
        `ws://127.0.0.1:${restarted.relay.ports.main}`,
        agentKey,
        acpEnv,
      );
      await new Promise((resolve) => setTimeout(resolve, 2_000));
      expect(restartedAcp.exitCode).toBeNull();
      if (!restartedAcp.pid)
        throw new Error("restarted ACP listener has no pid");
      expect(await processTree(restartedAcp.pid)).toHaveLength(1);
      const restartLatencyMs = await sendAndAwaitAck(
        restarted.relay,
        restarted.id,
        senderKey,
        `${restarted.relay.name}-restart`,
      );
      console.log(
        JSON.stringify({
          idleProcessCounts: idleTrees.map((tree) => tree.length),
          initialLatencies,
          refilledProcessCounts: refilledTrees.map((tree) => tree.length),
          restartLatencyMs,
        }),
      );
    } catch (error) {
      console.error(await harness.logs());
      throw error;
    } finally {
      await harness.stop();
      await eventually(async () => {
        const survivors = (
          await Promise.all(
            harness.ownedPids.map(async (pid) => {
              try {
                process.kill(pid, 0);
                return pid;
              } catch {
                return undefined;
              }
            }),
          )
        ).filter((pid) => pid !== undefined);
        return survivors.length === 0 ? true : undefined;
      });
    }
  });
});
