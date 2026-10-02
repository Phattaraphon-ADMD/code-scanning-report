#!/usr/bin/env node
const { spawnSync } = require("child_process");

const INSTALL_URL = "https://cli.github.com";

function isGhInstalled() {
  const result = spawnSync("gh", ["--version"], { stdio: "ignore" });
  return !result.error && result.status === 0;
}

// Warn only: a failing postinstall would block "npm install" for users who pass --input.
if (!isGhInstalled()) {
  console.warn(
    [
      "",
      'code-scanning-report: the GitHub CLI ("gh") was not found on PATH.',
      `Install it from ${INSTALL_URL} (e.g. "winget install GitHub.cli" or "brew install gh"),`
      + ' then run "gh auth login".',
      "It is not needed when using --input with a local JSON file.",
      "",
    ].join("\n"),
  );
}
