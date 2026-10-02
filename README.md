# code-scanning-report

Fetch GitHub code-scanning and secret-scanning alerts (via the GitHub CLI), or compact a local Checkmarx SCA report, into a normalized JSON report.

## Prerequisites

- Node.js 18 or later
- [GitHub CLI (`gh`)](https://cli.github.com), installed and authenticated. Not required when using `--input` with a local file.

Install `gh`:

```sh
# Windows
winget install GitHub.cli

# macOS
brew install gh

# Linux: see https://github.com/cli/cli/blob/trunk/docs/install_linux.md
```

Then authenticate:

```sh
gh auth login
```

## Install

```sh
npm install -g code-scanning-report
```

A post-install check prints a warning if `gh` is not found on PATH. It never fails the install.

## Usage

```sh
code-scanning-report --help
code-scanning-report --repo owner/repo --type code-scanning
code-scanning-report --type checkmarx --input report.json
```
