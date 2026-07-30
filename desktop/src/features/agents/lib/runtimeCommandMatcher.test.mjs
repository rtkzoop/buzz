import assert from "node:assert/strict";
import test from "node:test";

import { findRuntimeForCommand } from "./runtimeCommandMatcher.ts";

const omplRuntime = {
  id: "ompl",
  label: "Oh My Pi",
  availability: "available",
  command: "/Users/example/.local/bin/ompl",
  binaryPath: "/Users/example/.local/bin/ompl",
  defaultArgs: ["acp"],
};

const otherRuntime = {
  id: "goose",
  label: "Goose",
  availability: "available",
  command: "/Users/example/bin/goose",
  binaryPath: "/Users/example/bin/goose",
  defaultArgs: ["--acp"],
};

test('ompl runtime + "ompl" -> ompl', () => {
  assert.equal(findRuntimeForCommand([omplRuntime], "ompl"), omplRuntime);
});

test('ompl runtime + "omp" -> ompl', () => {
  assert.equal(findRuntimeForCommand([omplRuntime], "omp"), omplRuntime);
});

test('ompl runtime + "/Users/example/bin/ompl" -> ompl', () => {
  assert.equal(
    findRuntimeForCommand([omplRuntime], "/Users/example/bin/ompl"),
    omplRuntime,
  );
});

test('ompl runtime + "/opt/homebrew/bin/omp" -> ompl', () => {
  assert.equal(
    findRuntimeForCommand([omplRuntime], "/opt/homebrew/bin/omp"),
    omplRuntime,
  );
});

test('ompl runtime + "C:\\Tools\\omp.exe" -> ompl', () => {
  assert.equal(
    findRuntimeForCommand([omplRuntime], "C:\\Tools\\omp.exe"),
    omplRuntime,
  );
});

test("ompl runtime + unrelated custom command -> undefined", () => {
  assert.equal(findRuntimeForCommand([omplRuntime], "custom-agent"), undefined);
});

test("other runtime + its exact resolved command -> that runtime", () => {
  assert.equal(
    findRuntimeForCommand(
      [omplRuntime, otherRuntime],
      "/Users/example/bin/goose",
    ),
    otherRuntime,
  );
});
