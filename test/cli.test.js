const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");

const cli = path.resolve(__dirname, "../bin/cli.js");

function runCli(directory, ...args) {
  return spawnSync(process.execPath, [cli, ...args], {
    cwd: directory,
    encoding: "utf8",
  });
}

test("compacts Checkmarx SCA to the default file and supports stdout and custom output", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "checkmarx-cli-"));
  try {
    const source = {
      RiskReportSummary: { ProjectName: "example" },
      Packages: [
        {
          Id: "pkg-1",
          Name: "pkg",
          Version: "1.0.0",
          PackagePaths: [[
            { Name: "root", Version: "2.0.0", IsDevelopment: true },
            { Name: "pkg", Version: "1.0.0" },
          ]],
          NextVersionWithoutVulnerabilities: "1.0.1",
        },
        { Id: "safe", Name: "safe", Version: "1.0.0" },
      ],
      Vulnerabilities: [{
        PackageId: "pkg-1",
        CveName: "CVE-2026-0001",
        Description: "Security issue",
        NextFixedVersion: "1.0.1",
        References: ["https://example.com/advisory"],
      }],
    };
    const input = path.join(directory, "report.json");
    fs.writeFileSync(input, JSON.stringify(source));

    const defaultRun = runCli(directory, "--type", "checkmarx", "--input", input);
    assert.equal(defaultRun.status, 0, defaultRun.stderr);
    const defaultOutput = path.join(directory, "security-checkmarx-alerts.json");
    const compact = JSON.parse(fs.readFileSync(defaultOutput, "utf8"));
    assert.deepEqual(compact.counts, { packages: 1, vulnerabilities: 1 });
    assert.deepEqual(compact.packages[0].paths[0], {
      development: true,
      packages: ["root@2.0.0", "pkg@1.0.0"],
    });
    assert.equal(compact.packages[0].nextSafeVersion, "1.0.1");
    assert.equal(compact.packages[0].vulnerabilities[0].id, "CVE-2026-0001");
    assert.equal(compact.packages[0].vulnerabilities[0].fixVersion, "1.0.1");

    fs.unlinkSync(defaultOutput);
    const stdoutRun = runCli(directory, "--type", "checkmarx", "--input", input, "--stdout");
    assert.equal(stdoutRun.status, 0, stdoutRun.stderr);
    assert.deepEqual(JSON.parse(stdoutRun.stdout), compact);
    assert.equal(fs.existsSync(defaultOutput), false);

    const customRun = runCli(directory, "--type", "checkmarx", "--input", input,
      "--output", "custom.json");
    assert.equal(customRun.status, 0, customRun.stderr);
    assert.deepEqual(JSON.parse(fs.readFileSync(path.join(directory, "custom.json"), "utf8")), compact);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("rejects invalid SCA input and protects the original report", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "checkmarx-cli-"));
  try {
    const input = path.join(directory, "report.json");
    fs.writeFileSync(input, '{"Packages":[],"Vulnerabilities":[]}');
    const overwrite = runCli(directory, "--type", "checkmarx", "--input", input,
      "--output", input);
    assert.notEqual(overwrite.status, 0);
    assert.match(overwrite.stderr, /Output path must differ/);
    assert.equal(fs.readFileSync(input, "utf8"), '{"Packages":[],"Vulnerabilities":[]}');

    assert.notEqual(runCli(directory, "--type", "checkmarx").status, 0);
    fs.writeFileSync(input, JSON.stringify({ Packages: [], Vulnerabilities: [{ PackageId: "missing" }] }));
    const invalid = runCli(directory, "--type", "checkmarx", "--input", input);
    assert.notEqual(invalid.status, 0);
    assert.match(invalid.stderr, /missing packages/);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("existing GitHub code-scanning local input still works", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "checkmarx-cli-"));
  try {
    fs.writeFileSync(path.join(directory, "alerts.json"), "[]");
    const run = runCli(directory, "--input", "alerts.json", "--stdout");
    assert.equal(run.status, 0, run.stderr);
    assert.deepEqual(JSON.parse(run.stdout).alerts, []);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

// A fake "gh" shell script cannot be spawned without a shell on Windows.
test("works with an older gh that has no --slurp and prints pages back-to-back", { skip: process.platform === "win32" }, () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "fake-gh-"));
  try {
    const fakeGh = path.join(directory, "gh");
    const pages = '[{"number":1,"secret_type":"a"}][{"number":2,"secret_type":"b"}]';
    fs.writeFileSync(
      fakeGh,
      `#!/bin/sh\nfor arg in "$@"; do [ "$arg" = "--slurp" ] && { echo "unknown flag: --slurp" >&2; exit 1; }; done\necho '${pages}'\n`,
      { mode: 0o755 },
    );

    const run = spawnSync(process.execPath, [cli, "--type", "secret-scanning", "--repo", "o/r", "--stdout"], {
      cwd: directory,
      encoding: "utf8",
      env: { ...process.env, PATH: `${directory}${path.delimiter}${process.env.PATH}` },
    });
    assert.equal(run.status, 0, run.stderr);
    assert.deepEqual(JSON.parse(run.stdout).alerts.map((alert) => alert.alert), [1, 2]);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
