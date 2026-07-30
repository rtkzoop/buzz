import { expect, test, type Page } from "@playwright/test";
import { mkdirSync } from "node:fs";
import path from "node:path";

import { waitForAnimations } from "../helpers/animations";
import { installMockBridge, TEST_IDENTITIES } from "../helpers/bridge";

const SCREENSHOT_DIR = path.join("test-results", "oh-my-pi-harness-selector");

const GOOSE_RUNTIME = {
  id: "goose",
  label: "Goose",
  avatar_url: "",
  availability: "available",
  command: "goose",
  binary_path: "/usr/local/bin/goose",
  default_args: ["acp"],
  mcp_command: null,
  install_hint: "Install Goose via the official install script.",
  install_instructions_url: "https://block.github.io/goose/",
  can_auto_install: true,
  requires_external_cli: true,
  underlying_cli_path: null,
  node_required: false,
  auth_status: { status: "not_applicable" },
  login_hint: undefined,
};

const AVAILABLE_OMPL_RUNTIME = {
  id: "ompl",
  label: "Oh My Pi",
  avatar_url: "",
  availability: "available",
  command: "ompl",
  binary_path: "/Users/example/.local/bin/ompl",
  default_args: ["acp"],
  mcp_command: null,
  install_hint: "Install Oh My Pi with the official installer.",
  install_instructions_url: "https://ohmypi.example/install",
  can_auto_install: false,
  requires_external_cli: true,
  underlying_cli_path: null,
  node_required: false,
  auth_status: { status: "not_applicable" },
  login_hint: undefined,
};

const UNAVAILABLE_OMPL_RUNTIME = {
  ...AVAILABLE_OMPL_RUNTIME,
  availability: "not_installed",
  command: null,
  binary_path: null,
};

const AGENT_PUBKEY = TEST_IDENTITIES.tyler.pubkey;
const AGENT_NAME = "Oh My Pi Agent";

function ensureScreenshotDir() {
  mkdirSync(SCREENSHOT_DIR, { recursive: true });
}

async function captureDialog(page: Page, testId: string, name: string) {
  ensureScreenshotDir();
  await waitForAnimations(page);
  await page.getByTestId(testId).screenshot({
    path: path.join(SCREENSHOT_DIR, `${name}.png`),
  });
}

async function captureOpenMenu(page: Page, name: string) {
  ensureScreenshotDir();
  await waitForAnimations(page);
  await page
    .getByRole("menu")
    .last()
    .screenshot({
      path: path.join(SCREENSHOT_DIR, `${name}.png`),
    });
}

async function openCreateAgentDialog(page: Page) {
  await page.goto("/");
  await page.getByTestId("open-agents-view").click();
  await page.getByRole("button", { name: "New agent" }).click();
  await page.getByRole("menuitem", { name: "Create from scratch" }).click();
  await expect(page.getByTestId("persona-dialog")).toBeVisible({
    timeout: 10_000,
  });
}

async function openEditDialog(page: Page) {
  await page.goto("/");
  await page.getByTestId("open-agents-view").click();

  const agentButton = page.getByRole("button", {
    name: `${AGENT_NAME} agent profile`,
  });
  await expect(agentButton).toBeVisible({ timeout: 10_000 });
  await agentButton.click();

  await expect(page.getByTestId("user-profile-panel")).toBeVisible({
    timeout: 10_000,
  });
  await page.getByTestId("user-profile-edit-agent").click();

  await expect(page.getByTestId("edit-agent-dialog")).toBeVisible({
    timeout: 10_000,
  });
}

async function openAgentRuntimeSettings(page: Page) {
  await page.goto("/", { waitUntil: "domcontentloaded" });
  await page.getByTestId("open-settings").click();
  await page.getByTestId("profile-popover-settings").click();
  await expect(page.getByTestId("settings-view")).toBeVisible();
  await page.getByTestId("settings-nav-agents").click();
  await expect(page.getByTestId("settings-agent-runtimes")).toBeVisible({
    timeout: 10_000,
  });
}

async function pickDropdownOption(page: Page, triggerId: string, name: string) {
  await page.locator(`#${triggerId}`).click();
  await page.getByRole("menuitemradio", { name }).click();
}

function bridgeConfig(mock: Record<string, unknown>) {
  return mock as Parameters<typeof installMockBridge>[1];
}

async function invokeMockCommand<T>(
  page: Page,
  command: string,
  payload?: unknown,
) {
  return page.evaluate(
    async ({ command, payload }) => {
      const invoke = window.__BUZZ_E2E_INVOKE_MOCK_COMMAND__;
      if (!invoke) {
        throw new Error("Mock command invoker is not installed");
      }
      return (await invoke(command, payload)) as T;
    },
    { command, payload },
  );
}

test.describe("Oh My Pi harness selector", () => {
  test("creates from scratch with Oh My Pi selectable and provider hidden", async ({
    page,
  }) => {
    await installMockBridge(
      page,
      bridgeConfig({
        acpRuntimesCatalog: [GOOSE_RUNTIME, AVAILABLE_OMPL_RUNTIME],
      }),
    );

    await openCreateAgentDialog(page);
    await page.getByRole("tab", { name: "Customize for this agent" }).click();
    await expect(
      page.getByTestId("agent-custom-configuration-section"),
    ).toBeVisible();
    await expect(page.locator("#persona-runtime")).toBeVisible({
      timeout: 10_000,
    });

    await page.locator("#persona-runtime").click();
    await expect(
      page.getByRole("menuitemradio", { name: "Oh My Pi" }),
    ).toBeVisible();
    await captureOpenMenu(page, "create-runtime-menu-available");
    await page.getByRole("menuitemradio", { name: "Oh My Pi" }).click();

    await expect(page.locator("#persona-runtime")).toHaveText("Oh My Pi");
    await expect(page.locator("#persona-llm-provider")).toHaveCount(0);
    await page.locator("#persona-model").click();
    await page.getByRole("button", { name: "Custom model..." }).click();
    await page.locator("#persona-custom-model").fill("ompl-default");
    await page.locator("#persona-display-name").fill("Oh My Pi Scratch");
    await expect(page.getByTestId("persona-dialog-submit")).toBeEnabled();
    await expect(
      page.getByText("Visit Settings > Agents to set it up."),
    ).toHaveCount(0);
    await expect(
      page.getByTestId("persona-advanced-required-badge"),
    ).toHaveCount(0);
    await captureDialog(page, "persona-dialog", "create-oh-my-pi-selected");
  });

  test("shows unavailable Oh My Pi and setup guidance through the existing unavailable UI", async ({
    page,
  }) => {
    await installMockBridge(
      page,
      bridgeConfig({
        acpRuntimesCatalog: [GOOSE_RUNTIME, UNAVAILABLE_OMPL_RUNTIME],
      }),
    );

    await openCreateAgentDialog(page);
    await page.getByRole("tab", { name: "Customize for this agent" }).click();
    await expect(
      page.getByTestId("agent-custom-configuration-section"),
    ).toBeVisible();
    await page.locator("#persona-runtime").click();

    const unavailableItem = page.getByRole("menuitemradio", {
      name: "Oh My Pi (not installed)",
    });
    await expect(unavailableItem).toBeVisible();
    await expect(unavailableItem).toHaveAttribute("data-disabled", "");
    await captureOpenMenu(page, "create-runtime-menu-unavailable");

    await expect(
      page.getByRole("menuitemradio", { name: "Goose (default)" }),
    ).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(page.locator("#persona-runtime")).toHaveText(
      "Goose (default)",
    );
    await captureDialog(page, "persona-dialog", "create-unavailable-guidance");

    await page.getByRole("button", { name: "Cancel" }).click();
    await expect(page.getByTestId("persona-dialog")).not.toBeVisible();
    await openAgentRuntimeSettings(page);
    const runtimeCard = page.getByTestId("doctor-runtime-ompl");
    await expect(runtimeCard).toBeVisible({ timeout: 10_000 });
    await expect(
      page.getByTestId("doctor-runtime-guidance-ompl"),
    ).toContainText("Install Oh My Pi with the official installer.");
    const setupGuide = runtimeCard.getByRole("button", {
      name: "CLI setup guide",
    });
    await expect(setupGuide).toBeVisible();
    await invokeMockCommand(page, "clear_e2e_opened_external_urls");
    await setupGuide.click();
    await expect
      .poll(() =>
        invokeMockCommand<string[]>(page, "get_e2e_opened_external_urls"),
      )
      .toContain("https://ohmypi.example/install");
  });

  test("opens an Oh My Pi seeded agent with runtime and arguments resolved", async ({
    page,
  }) => {
    await installMockBridge(
      page,
      bridgeConfig({
        acpRuntimesCatalog: [GOOSE_RUNTIME, AVAILABLE_OMPL_RUNTIME],
        managedAgents: [
          {
            pubkey: AGENT_PUBKEY,
            name: AGENT_NAME,
            status: "stopped",
            channelNames: ["agents"],
            agentCommand: "/Users/example/.local/bin/ompl",
            agentCommandOverride: "/Users/example/.local/bin/ompl",
            agentArgs: ["acp"],
          },
        ],
      }),
    );

    await openEditDialog(page);

    await expect(page.locator("#edit-agent-runtime")).toHaveText("Oh My Pi", {
      timeout: 10_000,
    });
    await page.getByRole("button", { name: "Advanced", exact: true }).click();
    await expect(page.locator("#edit-agent-args")).toHaveValue("acp");
    await captureDialog(page, "edit-agent-dialog", "edit-seeded-oh-my-pi");
  });

  test("persists switching a bare omp seed to Oh My Pi through the update mutation", async ({
    page,
  }) => {
    await installMockBridge(
      page,
      bridgeConfig({
        acpRuntimesCatalog: [GOOSE_RUNTIME, AVAILABLE_OMPL_RUNTIME],
        managedAgents: [
          {
            pubkey: AGENT_PUBKEY,
            name: AGENT_NAME,
            status: "stopped",
            channelNames: ["agents"],
            agentCommand: "omp",
            agentCommandOverride: "omp",
            agentArgs: [],
            provider: "anthropic",
          },
        ],
      }),
    );

    await page.goto("/");

    const seededAgent = (
      await invokeMockCommand<
        Array<{
          pubkey: string;
          provider: string | null;
        }>
      >(page, "list_managed_agents")
    ).find((agent) => agent.pubkey === AGENT_PUBKEY);
    expect(seededAgent).toMatchObject({
      provider: "anthropic",
    });

    await openEditDialog(page);
    await pickDropdownOption(page, "edit-agent-runtime", "Oh My Pi");
    await expect(page.locator("#edit-agent-runtime")).toHaveText("Oh My Pi");
    await page.getByTestId("edit-agent-dialog-submit").click();
    await expect(page.getByTestId("edit-agent-dialog")).not.toBeVisible();

    const savedAgent = (
      await invokeMockCommand<
        Array<{
          pubkey: string;
          agent_command: string;
          agent_args: string[];
          provider: string | null;
        }>
      >(page, "list_managed_agents")
    ).find((agent) => agent.pubkey === AGENT_PUBKEY);
    expect(savedAgent).toMatchObject({
      agent_command: "ompl",
      agent_args: ["acp"],
      provider: null,
    });
    expect(savedAgent?.agent_command).not.toBe("omp");

    await page.getByTestId("user-profile-edit-agent").click();
    await expect(page.getByTestId("edit-agent-dialog")).toBeVisible({
      timeout: 10_000,
    });
    await expect(page.locator("#edit-agent-runtime")).toHaveText("Oh My Pi", {
      timeout: 10_000,
    });
    await page.getByRole("button", { name: "Advanced", exact: true }).click();
    await expect(page.locator("#edit-agent-args")).toHaveValue("acp");
    await captureDialog(page, "edit-agent-dialog", "edit-persisted-oh-my-pi");
  });
});
