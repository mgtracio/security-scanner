# security-scanner

Harbor scanner for container image metadata that inspects build history entries for configuration mistakes, redacted secret indicators, and Harbor vulnerability reports.

The scanner calls the Harbor v2 API, walks projects, repositories, artifacts, build history additions, and vulnerability additions, then writes CSV findings to standard output.

## Architecture

- `main.go`: CLI entry point, flags, interactive fallback, scanner orchestration.
- `apis/entries`: Harbor API entry paths to scan. The default starts at `/api/v2.0/projects`.
- `services/http`: HTTP client with timeout and secure TLS defaults.
- `services/rules`: API entry file loading.
- `services/url`: Harbor URL normalization.
- `services/scanner`: Harbor traversal, bounded repository scanning, secret detection, vulnerability parsing, and CSV finding generation.
- `services/scanner/entities`: Harbor API response models.
- `utils`: string matching and safe finding truncation helpers.

## Build and test

```bash
go test ./...
go vet ./...
go build -o security-scanner .
```

If your local environment blocks the default Go build cache, use a repo-local cache:

```bash
GOCACHE="$PWD/.cache/go-build" go test ./...
```

## Authors

- [Marco Guillén - @mgtracio](https://github.com/mgtracio)

## Installation

Install security-scanner by cloning the project.

```bash
  git clone https://github.com/mgtracio/security-scanner.git
  cd security-scanner
```

## Usage

Run non-interactively:

```bash
go run . -base-url https://harbor.example.com > findings.csv
```

Run interactively:

```bash
go run .
Enter the Harbor base url:
```

Flags:

- `-base-url`: Harbor base URL, for example `https://harbor.example.com`.
- `-entries`: path to the API entries file. Defaults to `./apis/entries`.
- `-timeout`: HTTP request timeout. Defaults to `30s`.
- `-insecure-skip-tls-verify`: allow self-signed or otherwise invalid Harbor TLS certificates.
- `-scan-vulnerabilities`: scan Harbor artifact vulnerability reports. Defaults to `true`.
- `-min-vulnerability-severity`: minimum vulnerability severity to emit. Supported values are `unknown`, `negligible`, `low`, `medium`, `high`, and `critical`. Defaults to `low`.
- `-concurrency`: maximum concurrent Harbor repository scans. Defaults to `4`.

Operational messages are written to stderr. CSV findings are written to stdout so shell redirection produces a clean CSV file.

## Security notes

- Harbor vulnerability reports are requested with `X-Accept-Vulnerabilities` for Harbor's v1.0 and v1.1 report media types.
- TLS certificate verification is enabled by default.
- Use `-insecure-skip-tls-verify` only for controlled development or lab Harbor instances with self-signed certificates.
- Do not commit Harbor credentials or exported scan output containing sensitive findings.
- Prefer running the scanner with a Harbor account that has read-only access to the projects being assessed.
- Build-history secret detection is assignment-aware and redacts values before writing CSV output. Findings identify the variable or signal, not the secret value.
- Review and rotate any secret-like values detected in build history. The scanner reports indicators; humans should validate whether each finding is an actual secret.
- Treat CVE rows as scanner intelligence from Harbor's configured scanner. Confirm exploitability, package reachability, and available fixes before production remediation.

## Test coverage

The current test suite covers:

- HTTP TLS verification defaults and the explicit insecure override.
- API entry parsing, including comments, blank lines, and missing files.
- Harbor URL normalization.
- Scanner traversal through projects, repositories, artifacts, and build history.
- Harbor vulnerability report parsing and severity filtering.
- Build-history secret assignment detection, redaction, references, and false-positive reduction.
- Bounded repository concurrency.
- CSV-safe finding output.
- Continuing artifact scanning when Harbor reports unsupported build history.

Useful follow-up coverage:

- End-to-end integration tests against a mocked Harbor API server.
- Authentication flows if Harbor credentials are added.
- Larger fixture sets for multiple Harbor scanner adapters, empty tags, malformed JSON, and non-2xx Harbor responses.
- Benchmarks for large registries and concurrency changes if parallel scanning is introduced.

## Contributing

Contributions are welcome. Please open an issue or contact the maintainer before large architecture changes.
