#!/usr/bin/env node
const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

const DEFAULT_OUTPUT = "security-alerts.json";
const DEFAULT_CHECKMARX_OUTPUT = "security-checkmarx-alerts.json";
const VALID_TYPES = ["code-scanning", "secret-scanning", "checkmarx", "all"];
const DEFAULT_TYPE = "code-scanning";
// Generic and AI-detected patterns are only returned by the API when requested by name.
const GENERIC_SECRET_TYPES = [
  "ec_private_key",
  "generic_private_key",
  "http_basic_authentication_header",
  "http_bearer_authentication_header",
  "mongodb_connection_string",
  "mysql_connection_url",
  "openssh_private_key",
  "pgp_private_key",
  "postgres_connection_string",
  "rsa_private_key",
  "password",
];
const STATES_BY_TYPE = {
  "code-scanning": ["open", "closed", "dismissed", "fixed", "all"],
  "secret-scanning": ["open", "resolved", "all"],
};
// Only allow simple "owner/repo" values; this is passed to "gh api" as a URL segment.
const REPO_PATTERN = /^[\w.-]+\/[\w.-]+$/;

const HELP_TEXT = `Usage: code-scanning-report [options]

Fetch GitHub code-scanning and/or secret-scanning alerts (via the GitHub
CLI), or compact a local Checkmarx SCA report for remediation.

Options:
  -t, --type <type>        Alert type: code-scanning, secret-scanning,
                           checkmarx, all (GitHub types only)
                           (default: ${DEFAULT_TYPE})
  -r, --repo <owner/repo>  Target GitHub repository (default: detected by "gh"
                           from the git remote of the current directory)
  -s, --state <state>      GitHub alert state to fetch (default: open)
                           code-scanning:   open, closed, dismissed, fixed, all
                           secret-scanning: open, resolved, all
  -i, --input <path>       Read a local JSON file instead of calling the
                           GitHub API (required for checkmarx)
  -o, --output <path>      Output file path (default: ${DEFAULT_OUTPUT},
                           or ${DEFAULT_CHECKMARX_OUTPUT} for checkmarx);
                           with --type all, one file per type is written
                           as <name>.<type>.json
      --stdout             Print the normalized report to stdout instead
                           of writing a file
  -h, --help               Show this help message

Requires the GitHub CLI ("gh") to be installed and authenticated
(run "gh auth login") when --input is not used.
Example: code-scanning-report --type checkmarx --input report.json
`;

function parseArgs(argv) {
  const args = {
    type: DEFAULT_TYPE,
    repo: null,
    state: "open",
    input: null,
    output: null,
    stdout: false,
    help: false,
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];

    switch (arg) {
      case "-h":
      case "--help":
        args.help = true;
        break;
      case "-t":
      case "--type":
        args.type = argv[++i];
        break;
      case "-r":
      case "--repo":
        args.repo = argv[++i];
        break;
      case "-s":
      case "--state":
        args.state = argv[++i];
        break;
      case "-i":
      case "--input":
        args.input = argv[++i];
        break;
      case "-o":
      case "--output":
        args.output = argv[++i];
        break;
      case "--stdout":
        args.stdout = true;
        break;
      default:
        console.error(`Unknown argument: ${arg}`);
        process.exit(1);
    }
  }

  if (args.repo && !REPO_PATTERN.test(args.repo)) {
    console.error(`Invalid --repo value: "${args.repo}". Expected format "owner/repo".`);
    process.exit(1);
  }

  if (!VALID_TYPES.includes(args.type)) {
    console.error(
      `Invalid --type value: "${args.type}". Expected one of: ${VALID_TYPES.join(", ")}.`
    );
    process.exit(1);
  }

  if (args.input && args.type === "all") {
    console.error('--input requires --type "code-scanning" or "secret-scanning".');
    process.exit(1);
  }

  if (args.type === "checkmarx" && !args.input) {
    console.error('--type "checkmarx" requires --input with a local SCA report.');
    process.exit(1);
  }

  for (const type of selectedTypes(args.type)) {
    if (STATES_BY_TYPE[type] && !STATES_BY_TYPE[type].includes(args.state)) {
      console.error(
        `Invalid --state value for ${type}: "${args.state}". Expected one of: ${STATES_BY_TYPE[type].join(", ")}.`
      );
      process.exit(1);
    }
  }

  args.output ||= args.type === "checkmarx" ? DEFAULT_CHECKMARX_OUTPUT : DEFAULT_OUTPUT;
  return args;
}

function selectedTypes(type) {
  return type === "all" ? Object.keys(STATES_BY_TYPE) : [type];
}

function repoSegmentFor(repo) {
  // "{owner}/{repo}" is resolved by "gh" itself from the current directory's git remote.
  return repo || "{owner}/{repo}";
}

function ghApiPaginate(endpoint) {
  // Array args (no shell) avoid command injection even though --repo is already validated above.
  const result = spawnSync("gh", ["api", "--paginate", "--slurp", endpoint], {
    encoding: "utf8",
    maxBuffer: 1024 * 1024 * 64,
  });

  if (result.error) {
    throw new Error(`Failed to run the GitHub CLI ("gh"). Is it installed and on PATH?\n${result.error.message}`);
  }

  if (result.status !== 0) {
    throw new Error(
      `"gh api" exited with code ${result.status}.\n${(result.stderr || result.stdout || "").trim()}`
    );
  }

  // "--slurp" wraps each page's array into an outer array; flatten back to one list.
  return JSON.parse(result.stdout || "[]").flat();
}

function fetchAlertsFromGitHub(repo, state, type, extraQuery = "") {
  const stateQuery = state === "all" ? "" : `&state=${encodeURIComponent(state)}`;
  const endpoint = `repos/${repoSegmentFor(repo)}/${type}/alerts?per_page=100${stateQuery}${extraQuery}`;

  try {
    return ghApiPaginate(endpoint);
  } catch (error) {
    console.error(error.message);
    process.exit(1);
  }
}

function fetchSecretLocations(repo, alertNumber) {
  const endpoint = `repos/${repoSegmentFor(repo)}/secret-scanning/alerts/${Number(alertNumber)}/locations?per_page=100`;

  try {
    return ghApiPaginate(endpoint);
  } catch (error) {
    // A single failed lookup should not abort the whole report.
    console.error(`Could not fetch locations for alert #${alertNumber}: ${error.message.split("\n")[0]}`);
    return null;
  }
}

function fetchSecretScanningAlerts(repo, state) {
  // hide_secret keeps raw secret values out of the API response entirely.
  const hideSecretQuery = "&hide_secret=true";
  const genericQuery = `${hideSecretQuery}&secret_type=${GENERIC_SECRET_TYPES.join(",")}`;

  const defaultAlerts = fetchAlertsFromGitHub(repo, state, "secret-scanning", hideSecretQuery);
  const genericAlerts = fetchAlertsFromGitHub(repo, state, "secret-scanning", genericQuery);

  const byNumber = new Map();
  for (const alert of [...defaultAlerts, ...genericAlerts]) {
    byNumber.set(alert.number, alert);
  }

  // The list endpoint only returns the first location; the agent needs every one to fix them all.
  return [...byNumber.values()].map((alert) => ({
    ...alert,
    locations: fetchSecretLocations(repo, alert.number),
  }));
}

function parseMessage(text = "") {
  const result = {};

  for (const line of text.split("\n")) {
    const index = line.indexOf(":");
    if (index === -1) continue;

    const key = line.slice(0, index).trim();
    const value = line.slice(index + 1).trim();

    if (key === "Package") {
      result.package = value;
    } else if (key === "Installed Version") {
      result.installed = value;
    } else if (key === "Fixed Version") {
      result.fixedVersions = value
        .split(",")
        .map((v) => v.trim())
        .filter(Boolean);
    } else if (key === "Severity") {
      result.severity = value.toUpperCase();
    }
  }

  return result;
}

function parseVersion(version) {
  if (!version) return null;

  // Strip common prefixes such as v1.2.3
  const cleaned = version.trim().replace(/^v/, "");

  const match = cleaned.match(/^(\d+)\.(\d+)\.(\d+)/);

  if (!match) return null;

  return {
    raw: version,
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3]),
  };
}

function compareVersions(a, b) {
  const va = parseVersion(a);
  const vb = parseVersion(b);

  if (!va && !vb) return 0;
  if (!va) return 1;
  if (!vb) return -1;

  if (va.major !== vb.major) return va.major - vb.major;
  if (va.minor !== vb.minor) return va.minor - vb.minor;
  return va.patch - vb.patch;
}

function chooseTargetVersion(installed, fixedVersions) {
  if (!fixedVersions || fixedVersions.length === 0) {
    return null;
  }

  const installedVersion = parseVersion(installed);

  const valid = fixedVersions
    .filter((v) => parseVersion(v))
    .sort(compareVersions);

  if (valid.length === 0) {
    return fixedVersions[0] || null;
  }

  if (!installedVersion) {
    return valid[0];
  }

  // Prefer staying on the current major version.
  const sameMajor = valid.filter(
    (v) => parseVersion(v)?.major === installedVersion.major
  );

  if (sameMajor.length > 0) {
    return sameMajor[0];
  }

  // If no patched version exists in the same major,
  // choose the lowest available fixed version.
  return valid[0];
}

function severityRank(severity) {
  const ranks = {
    UNKNOWN: 0,
    LOW: 1,
    MEDIUM: 2,
    MODERATE: 2,
    HIGH: 3,
    CRITICAL: 4,
  };

  return ranks[String(severity || "").toUpperCase()] || 0;
}

function highestSeverity(current, candidate) {
  if (!current) return candidate || "UNKNOWN";
  if (!candidate) return current;

  return severityRank(candidate) > severityRank(current)
    ? candidate
    : current;
}

function normalizeSummary(description) {
  if (!description) return "";

  return description
    .replace(/\s+/g, " ")
    .trim();
}

function loadJsonFromFile(inputPath) {
  if (!fs.existsSync(inputPath)) {
    console.error(`Input file not found: ${inputPath}`);
    process.exit(1);
  }

  let report;

  try {
    report = JSON.parse(fs.readFileSync(inputPath, "utf8"));
  } catch (error) {
    console.error(`Failed to parse ${inputPath}:`);
    console.error(error.message);
    process.exit(1);
  }

  return report;
}

function loadAlertsFromFile(inputPath) {
  const alerts = loadJsonFromFile(inputPath);
  if (!Array.isArray(alerts)) {
    console.error("Expected the alerts source to contain an array of alerts.");
    process.exit(1);
  }

  return alerts;
}

function compactCheckmarxVulnerability(vulnerability) {
  return {
    id: vulnerability.CveName || vulnerability.Id,
    severity: vulnerability.Severity,
    score: vulnerability.Score,
    cwe: vulnerability.Cwe,
    description: vulnerability.Description,
    references: vulnerability.References,
    fixVersion: vulnerability.NextFixedVersion,
    latestFixedVersion: vulnerability.LatestFixedVersion,
    fixResolution: vulnerability.FixResolutionText,
    ignored: vulnerability.IsIgnored,
    riskState: vulnerability.RiskState,
    violatesPolicy: vulnerability.IsViolatingPolicy,
    exploitabilityStatus: vulnerability.ExploitabilityStatus,
    exploitabilityReason: vulnerability.ExploitabilityReason,
  };
}

function compactCheckmarxPackage(dependency, vulnerabilities) {
  return {
    name: dependency.Name,
    version: dependency.Version,
    direct: dependency.IsDirectDependency,
    development: dependency.IsDevelopmentDependency,
    locations: dependency.Locations,
    paths: (dependency.PackagePaths || []).map((dependencyPath) => ({
      development: dependencyPath[0]?.IsDevelopment || false,
      packages: dependencyPath.map((entry) => `${entry.Name}@${entry.Version}`),
    })),
    nextSafeVersion: dependency.NextVersionWithoutVulnerabilities,
    latestSafeVersion: dependency.LatestVersionWithoutVulnerabilities,
    violatesPolicy: dependency.IsViolatingPolicy,
    vulnerabilities,
  };
}

function buildCheckmarxReport(source) {
  if (!source || !Array.isArray(source.Packages) || !Array.isArray(source.Vulnerabilities)) {
    throw new Error("Expected a Checkmarx SCA report with Packages and Vulnerabilities arrays");
  }

  const vulnerabilitiesByPackage = new Map();
  for (const vulnerability of source.Vulnerabilities) {
    const findings = vulnerabilitiesByPackage.get(vulnerability.PackageId) || [];
    findings.push(compactCheckmarxVulnerability(vulnerability));
    vulnerabilitiesByPackage.set(vulnerability.PackageId, findings);
  }

  const packages = source.Packages.filter((dependency) =>
    vulnerabilitiesByPackage.has(dependency.Id)
  ).map((dependency) =>
    compactCheckmarxPackage(dependency, vulnerabilitiesByPackage.get(dependency.Id))
  );

  const packageIds = new Set(source.Packages.map((dependency) => dependency.Id));
  const missingPackages = [...vulnerabilitiesByPackage.keys()].filter(
    (packageId) => !packageIds.has(packageId)
  );
  if (missingPackages.length) {
    throw new Error(`Vulnerabilities reference missing packages: ${missingPackages.join(", ")}`);
  }

  const report = {
    project: source.RiskReportSummary?.ProjectName,
    scannedAt: source.RiskReportSummary?.CreatedOn,
    counts: { packages: packages.length, vulnerabilities: source.Vulnerabilities.length },
    packages,
  };
  return {
    report,
    summaryLines: [
      `Vulnerable packages: ${report.counts.packages}`,
      `Vulnerabilities:     ${report.counts.vulnerabilities}`,
    ],
  };
}

const SECRET_AGENT_INSTRUCTIONS = [
  "Fix each alert by editing the files listed in its locations; the raw secret value is intentionally not included.",
  "Locations come from the commit where the secret was detected; the file or line may have moved at HEAD, so search by path first.",
  "Replace hardcoded secrets with environment variables or a secrets manager, and never write a real secret back into the repo.",
  "Do not rewrite git history or close alerts; those steps need a human (see humanFollowUp).",
];

const SECRET_HUMAN_FOLLOW_UP = [
  "Revoke or rotate every exposed credential; removing it from code does not make it safe.",
  "Purge the secret from git history if required by policy.",
  "Close the alert on GitHub (for example as revoked) once the credential is rotated.",
];

function remediationFor(secretType = "") {
  if (secretType.endsWith("_private_key")) {
    return [
      "Remove the private key file or inline key from the repository.",
      "Load the key at runtime from a secret store or an untracked path, or generate a throwaway key if it is only a test fixture.",
      "Add the key path to .gitignore.",
    ];
  }

  if (secretType.endsWith("_authentication_header")) {
    return [
      "Remove the hardcoded Authorization header value.",
      "Build the header at runtime from an environment variable or secrets manager.",
    ];
  }

  if (secretType.includes("connection")) {
    return [
      "Remove the credentials from the connection string.",
      "Read the connection string from an environment variable or secrets manager.",
    ];
  }

  return [
    "Remove the hardcoded secret from the source.",
    "Read it at runtime from an environment variable or secrets manager.",
  ];
}

function normalizeSecretLocation(location) {
  const details = location.details || {};
  const normalized = {
    type: location.type,
    path: details.path,
    startLine: details.start_line,
    endLine: details.end_line,
    startColumn: details.start_column,
    endColumn: details.end_column,
    commitSha: details.commit_sha,
  };

  return Object.fromEntries(
    Object.entries(normalized).filter(([, value]) => value !== undefined && value !== null)
  );
}

function secretLocationsOf(alert) {
  if (Array.isArray(alert.locations)) {
    return alert.locations.map(normalizeSecretLocation);
  }

  // Fall back to the single location included in the list response.
  return alert.first_location_detected
    ? [normalizeSecretLocation({ details: alert.first_location_detected })]
    : [];
}

function groupSecretAlertsByFile(alerts) {
  const files = new Map();

  for (const alert of alerts) {
    for (const location of alert.locations) {
      if (!location.path) continue;

      if (!files.has(location.path)) {
        files.set(location.path, { path: location.path, alerts: new Set() });
      }

      files.get(location.path).alerts.add(alert.alert);
    }
  }

  return [...files.values()]
    .map((file) => ({ path: file.path, alerts: [...file.alerts].sort((a, b) => a - b) }))
    .sort((a, b) => a.path.localeCompare(b.path));
}

function buildSecretScanningReport(alerts, state) {
  const normalizedAlerts = alerts
    // The GitHub API already filters by state; this also covers --input files with mixed states.
    .filter((alert) => state === "all" || !alert.state || alert.state === state)
    // The raw "secret" value is deliberately never copied into the report.
    .map((alert) => ({
      alert: alert.number,
      secretType: alert.secret_type || null,
      category: GENERIC_SECRET_TYPES.includes(alert.secret_type) ? "generic" : "default",
      secretTypeDisplayName: alert.secret_type_display_name || null,
      state: alert.state || null,
      resolution: alert.resolution || null,
      validity: alert.validity || null,
      publiclyLeaked: alert.publicly_leaked ?? null,
      createdAt: alert.created_at || null,
      url: alert.html_url || null,
      locations: secretLocationsOf(alert),
      remediation: remediationFor(alert.secret_type),
    }))
    .sort(
      (a, b) =>
        String(a.secretType).localeCompare(String(b.secretType)) ||
        (a.alert || 0) - (b.alert || 0)
    );

  const report = {
    scope: "secret-scanning-alerts",
    source: "github-secret-scanning",
    agentInstructions: SECRET_AGENT_INSTRUCTIONS,
    humanFollowUp: SECRET_HUMAN_FOLLOW_UP,
    files: groupSecretAlertsByFile(normalizedAlerts),
    alerts: normalizedAlerts,
  };

  const summaryLines = [
    `Input alerts:      ${alerts.length}`,
    `Reported alerts:   ${normalizedAlerts.length}`,
  ];

  for (const item of normalizedAlerts) {
    summaryLines.push(
      `- #${item.alert} ${item.secretTypeDisplayName || item.secretType || "?"} (${item.state || "?"}, validity: ${item.validity || "unknown"})`
    );
  }

  return { report, summaryLines };
}

function buildCodeScanningReport(alerts, state) {
  const groups = new Map();
  const skipped = [];

  for (const alert of alerts) {
    // The GitHub API already filters by state; this also covers --input files with mixed states.
    if (state !== "all" && alert.state && alert.state !== state) {
      continue;
    }

    const message =
      alert.most_recent_instance?.message?.text || "";

    const parsed = parseMessage(message);

    const packageName = parsed.package;

    if (!packageName) {
      skipped.push({
        alert: alert.number,
        rule: alert.rule?.id || null,
        reason: "Unable to determine package name from alert message",
      });
      continue;
    }

    if (!groups.has(packageName)) {
      groups.set(packageName, {
        package: packageName,
        installed: parsed.installed || null,
        severity: null,

        _fixedVersions: new Set(),
        cves: [],
      });
    }

    const group = groups.get(packageName);

    if (!group.installed && parsed.installed) {
      group.installed = parsed.installed;
    }

    group.severity = highestSeverity(
      group.severity,
      parsed.severity ||
        alert.rule?.security_severity_level ||
        alert.rule?.severity
    );

    for (const version of parsed.fixedVersions || []) {
      group._fixedVersions.add(version);
    }

    group.cves.push({
      id: alert.rule?.id || null,
      alert: alert.number,
      severity:
        parsed.severity ||
        alert.rule?.security_severity_level?.toUpperCase() ||
        alert.rule?.severity?.toUpperCase() ||
        "UNKNOWN",
      summary: normalizeSummary(alert.rule?.description),
    });
  }

  const normalizedAlerts = [];

  for (const group of groups.values()) {
    const fixedVersions = [...group._fixedVersions].sort(compareVersions);

    /*
     * Important:
     *
     * If multiple CVEs affect the same package, simply selecting the
     * smallest fixed version from all alerts is not necessarily enough.
     *
     * Example:
     *
     * CVE-A fixed in 6.13.5
     * CVE-B fixed in 6.13.6
     *
     * We want 6.13.6.
     */

    let target = null;

    if (group.installed) {
      const installed = parseVersion(group.installed);

      if (installed) {
        const sameMajorVersions = fixedVersions.filter(
          (v) => parseVersion(v)?.major === installed.major
        );

        if (sameMajorVersions.length > 0) {
          // Highest fixed version within the current major ensures
          // all grouped vulnerability minimum versions are covered.
          target = sameMajorVersions.sort(compareVersions).at(-1);
        }
      }
    }

    if (!target && fixedVersions.length > 0) {
      /*
       * No fix exists in the currently installed major.
       * Choose the lowest major containing a fix, then the highest
       * required version inside that major.
       */
      const byMajor = new Map();

      for (const version of fixedVersions) {
        const parsed = parseVersion(version);

        if (!parsed) continue;

        if (!byMajor.has(parsed.major)) {
          byMajor.set(parsed.major, []);
        }

        byMajor.get(parsed.major).push(version);
      }

      const majors = [...byMajor.keys()].sort((a, b) => a - b);

      if (majors.length > 0) {
        const selectedMajor = majors[0];

        target = byMajor
          .get(selectedMajor)
          .sort(compareVersions)
          .at(-1);
      } else {
        target = fixedVersions[0];
      }
    }

    normalizedAlerts.push({
      package: group.package,
      installed: group.installed,
      target,
      severity: group.severity || "UNKNOWN",
      cves: group.cves.sort((a, b) => {
        const severityDiff =
          severityRank(b.severity) - severityRank(a.severity);

        if (severityDiff !== 0) {
          return severityDiff;
        }

        return (a.alert || 0) - (b.alert || 0);
      }),
    });
  }

  normalizedAlerts.sort((a, b) => {
    const severityDiff =
      severityRank(b.severity) - severityRank(a.severity);

    if (severityDiff !== 0) {
      return severityDiff;
    }

    return a.package.localeCompare(b.package);
  });

  const output = {
    scope: "fix-listed-alerts-only",
    source: "github-code-scanning",
    scanner:
      alerts.find((a) => a.tool?.name)?.tool?.name || null,
    alerts: normalizedAlerts,
  };

  if (skipped.length > 0) {
    output.skipped = skipped;
  }

  const summaryLines = [
    `Input alerts:      ${alerts.length}`,
    `Package groups:    ${normalizedAlerts.length}`,
    `Skipped alerts:    ${skipped.length}`,
  ];

  for (const item of normalizedAlerts) {
    summaryLines.push(
      `- ${item.package}: ${item.installed || "?"} -> ${
        item.target || "?"
      } (${item.cves.length} alert(s), ${item.severity})`
    );
  }

  return { report: output, summaryLines };
}

const REPORT_BUILDERS = {
  "code-scanning": buildCodeScanningReport,
  "secret-scanning": buildSecretScanningReport,
};

// "security-alerts.json" + "secret-scanning" -> "security-alerts.secret-scanning.json"
function outputPathForType(outputPath, type) {
  const { dir, name, ext } = path.parse(outputPath);
  return path.join(dir, `${name}.${type}${ext}`);
}

function main(args) {
  if (args.help) {
    console.log(HELP_TEXT);
    return;
  }

  const types = selectedTypes(args.type);
  const results = {};

  for (const type of types) {
    if (type === "checkmarx") {
      const source = loadJsonFromFile(args.input);
      try {
        results[type] = buildCheckmarxReport(source);
      } catch (error) {
        console.error(`Invalid Checkmarx SCA report: ${error.message}`);
        process.exitCode = 1;
        return;
      }
      continue;
    }

    const alerts = args.input
      ? loadAlertsFromFile(args.input)
      : type === "secret-scanning"
        ? fetchSecretScanningAlerts(args.repo, args.state)
        : fetchAlertsFromGitHub(args.repo, args.state, type);

    results[type] = REPORT_BUILDERS[type](alerts, args.state);
  }

  const toJson = (report) => JSON.stringify(report, null, 2) + "\n";
  const outputFiles = [];

  if (args.stdout) {
    // A single type keeps its original top-level shape; "all" nests one report per type.
    const output =
      types.length === 1
        ? results[types[0]].report
        : Object.fromEntries(types.map((type) => [type, results[type].report]));

    process.stdout.write(toJson(output));
  } else {
    for (const type of types) {
      const outputPath = types.length === 1 ? args.output : outputPathForType(args.output, type);
      if (args.input && path.resolve(args.input) === path.resolve(outputPath)) {
        console.error("Output path must differ from the input file.");
        process.exitCode = 1;
        return;
      }
      fs.writeFileSync(outputPath, toJson(results[type].report), "utf8");
      outputFiles.push(path.resolve(outputPath));
    }
  }

  // Status lines always go to stderr so --stdout output stays pipeable as clean JSON.
  for (const type of types) {
    if (types.length > 1) console.error(`[${type}]`);
    for (const line of results[type].summaryLines) console.error(line);
  }

  for (const outputFile of outputFiles) {
    console.error(`Output:            ${outputFile}`);
  }
}

main(parseArgs(process.argv.slice(2)));
