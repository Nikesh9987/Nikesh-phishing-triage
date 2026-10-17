# Phishing Triage & Header Parser

A SOC tool that turns a suspicious `.eml` or `.msg` file into a triage report: sender
authentication, the delivery path, indicators of compromise, attachment analysis,
threat-intelligence lookups and a 0-100 risk score. It ships as a **command-line tool**,
a **JSON API** and a **dark web dashboard**, all driven by one analysis engine.

> **A `clean` verdict means "no indicators found", not "safe".** A targeted phish sent
> from a compromised, fully authenticated account can legitimately score clean.
> Treat the score as a triage aid, not a ruling.

## What it does

| Area | Details |
|---|---|
| Parsing | `.eml` (standard library) and Outlook `.msg` (`extract-msg`). Format is detected from content, never from the file name. Attached emails are listed as attachments. |
| Authentication | SPF, DKIM and DMARC from `Authentication-Results` and `Received-SPF`, with identifier alignment (relaxed or strict, from the published DMARC record). DNS fallbacks when the headers say nothing. Only the topmost server's `Authentication-Results` is believed unless you pin one. |
| Delivery path | Every `Received` hop, oldest first: hosts, IPs, scope (public, RFC 1918, CGNAT, loopback...), reverse DNS, delays, clock-skew and forged-hop signals, and an estimate of the originating MTA. |
| Indicators | URLs, e-mail addresses, domains, IPv4 and IPv6 from headers, text and HTML (anchors, forms, scripts, comments, meta refresh). Input that is already defanged is understood. Output is defanged and safe to paste. |
| Attachments | MD5, SHA-1, SHA-256, magic-byte type detection, double extensions, direction-override names, disguised executables, macros (parse-only), remote templates, PDF/RTF/HTML/SVG indicators, encrypted and suspicious archives. Everything stays in memory. |
| Anomalies | Reply-To and Return-Path mismatches, display-name spoofing, lookalike and homograph domains, link text that shows one site but links to another, URL tricks, social-engineering language. |
| Threat intel | URLhaus, AbuseIPDB, VirusTotal (lookup only) and DNS blocklists, with rate limiting, a TTL cache, a per-run quota budget and graceful fallbacks. |

## Quick start

Requires Python 3.11 or newer.

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env            # optional: API keys and settings

phishtriage analyze suspicious.eml
```

Or with Docker (see `DEPLOYMENT.md` before exposing it to anyone):

```bash
docker compose up -d --build
# open http://127.0.0.1:8000/
```

## Command line

```bash
phishtriage analyze FILE...      # full report (tables, or --json)
phishtriage iocs    FILE...      # indicators only, ready for a ticket
phishtriage status               # configuration and provider state
```

Use `-` as the file name to read one message from standard input.

| Option | Applies to | Meaning |
|---|---|---|
| `--json` | analyze, status | JSON on stdout (one file: object; several: array) |
| `-o PATH` | analyze | also write the JSON report to a file |
| `--headers` | analyze | include all raw headers |
| `--fail-on LEVEL` | analyze | exit 10 if a verdict reaches `low_risk`, `suspicious` or `malicious` |
| `--no-enrich` | analyze | skip threat-intel lookups |
| `--enrich` | iocs | do threat-intel lookups (off by default for speed) |
| `--type T` | iocs | `url`, `email`, `ipv4`, `ipv6`, `domain`, `hash` (repeatable) |
| `--format F` | iocs | `table`, `text` (one defanged value per line) or `json` |
| `--no-hashes` | iocs | leave out attachment hashes |
| `--trusted-hops N` | analyze, iocs | the N newest `Received` hops belong to your servers |
| `--trusted-authserv ID` | analyze, iocs | believe only this authserv-id (repeatable) |
| `--no-macros` | analyze, iocs | skip the Office macro scan |
| `--offline` | all | no network activity at all |
| `-v`, `-vv` | all | log to stderr (info, debug) |

Results go to **stdout**, errors and logs to **stderr**, so pipes stay clean.

| Exit code | Meaning |
|---|---|
| 0 | success (any verdict) |
| 2 | bad input or arguments (missing, empty, oversized or unrecognised file) |
| 3 | the message could not be parsed |
| 10 | `--fail-on` threshold reached |
| 78 | invalid configuration |
| 130 | interrupted |

```bash
# Ticket-ready indicators
phishtriage iocs suspicious.eml --format text

# Gate a mail-processing script
phishtriage analyze suspicious.eml --json --fail-on suspicious > report.json || echo "quarantine"
```

## Web dashboard and API

```bash
phishtriage-api                  # or: python -m phishtriage.api.app
# uvicorn phishtriage.api.app:create_app --factory --host 127.0.0.1 --port 8000
```

The dashboard (`/`) offers drag-and-drop upload, a verdict card, SPF/DKIM/DMARC badges,
the hop-by-hop path, and indicator and hash tables with one-click copy buttons.

| Endpoint | Purpose |
|---|---|
| `GET /health` | liveness, version, provider state (never secrets) |
| `POST /api/analyze` | multipart upload (`file`, optional `trusted_hops`, `trusted_authserv`, `enrich`, `scan_macros`) |
| `GET /api/report/{id}` | fetch a stored report (`?download=true` for a file) |
| `DELETE /api/report/{id}` | delete a stored report |
| `GET /api/export/iocs/{id}` | defanged IOCs and hashes: `?format=json\|text\|csv`, `types`, `include_hashes`, `download` |

```bash
curl -s -F file=@suspicious.eml -F enrich=false http://127.0.0.1:8000/api/analyze | jq .summary
```

Errors are always JSON: `{"error": "<code>", "message": "...", "details": {...}}`.

Things to know:

* **There is no login.** Report ids are random bearer links. Put the service behind
  authentication (a reverse proxy) before exposing it beyond your SOC network.
* Reports live **in memory only** for one hour (200 at most), and a restart clears them.
* Run **one worker**. The report store, rate limiter and intel cache are per process.
* `/api/analyze` is rate limited per client address (default 30 per minute).

## Configuration

All settings come from environment variables or a `.env` file. `.env.example`
documents every one. The ones you will touch first:

| Variable | Default | Purpose |
|---|---|---|
| `PHISHTRIAGE_OFFLINE` | `false` | no DNS and no threat-intel traffic at all |
| `URLHAUS_AUTH_KEY`, `ABUSEIPDB_API_KEY`, `VIRUSTOTAL_API_KEY` | unset | enable those providers (all optional) |
| `PHISHTRIAGE_MAX_UPLOAD_BYTES` | 25 MiB | upload limit |
| `PHISHTRIAGE_DNS_NAMESERVERS` | system | custom resolvers (Spamhaus blocks big public ones) |
| `PHISHTRIAGE_API_RATE_LIMIT_PER_MINUTE` | 30 | per-client limit on analysis |
| `PHISHTRIAGE_LOG_FORMAT` | `text` | `json` for log shippers |

API keys are read only from the environment, held as secrets, and redacted from logs.
Only indicators (hashes, URLs, IPs, domains) are ever sent to providers. The message
itself never is, and internal or non-routable indicators are not sent either.

## How the score works

Findings are combined with a "noisy-OR": independent weak signals add up but saturate, so
routine low-severity noise never reaches `suspicious` on its own. A few high-confidence
findings (a disguised executable, a malicious macro pattern, a URL listed by URLhaus) set
a minimum score. When a minimum decides the result, a `score_floor_applied` finding says so.

| Score | Verdict |
|---|---|
| 70-100 | malicious |
| 40-69 | suspicious |
| 15-39 | low risk |
| 0-14 | clean (no indicators) |

Threat-intel `unknown`, `clean`, `error` and `skipped` results never add or remove
points: not being listed is weak evidence, and a provider outage must not change a
verdict. The weights are heuristics. Tune `CODE_POINTS`, `FLOORS` and `VERDICT_BANDS`
in `src/phishtriage/core/scoring.py` for your environment, and re-run the tests.

## Project layout

```
src/phishtriage/
  config.py, logging_config.py
  core/        models, exceptions, defang, utils, scoring, pipeline
  parsers/     base (sniffing, shared helpers), eml_parser, msg_parser
  analyzers/   ioc_extractor, received_tracer, auth_analyzer,
               attachment_analyzer, header_anomalies
  intel/       base (HTTP client, provider interface), rate_limiter, cache,
               urlhaus, abuseipdb, virustotal, dnsbl, aggregator
  cli/         main, render
  api/         app, routes, schemas, dependencies, templates/, static/
tests/         unit and end-to-end tests (no network)
```

Dependencies point one way: `core` at the bottom, then `parsers`, `analyzers` and
`intel`, with `core/pipeline.py` orchestrating them, and `cli` and `api` on top.

## Development

```bash
pip install -e ".[dev]"
pytest                          # about a thousand checks, no network, no real malware
ruff check src tests
mypy src
bandit -r src
pip-audit
```

Test samples are built in code from harmless bytes. Executables are 200-byte stubs
that cannot run, and macro analysis is tested through a fake at the `oletools` seam.

## Limitations

* **DKIM signatures are not cryptographically verified.** The raw message bytes are not
  retained. Without a verdict in the headers the key record is checked and the status is
  `unknown`, never a fake `pass`.
* **DNS-derived SPF is an estimate.** The built-in evaluator skips macros and `ptr`
  (status `unknown`) and needs the connecting IP. Forwarded mail will be misjudged.
* **The originating MTA is an estimate** unless you pass `--trusted-hops`. A sender can
  forge every `Received` line below your own servers.
* **PDF checks are keyword indicators.** Keywords inside compressed object streams are
  not visible, so a clean result is not proof of safety.
* Attachment contents are not mined for URLs, and attached emails are flagged but not
  analyzed recursively.
* Language checks are English only. The brand list for lookalike detection is small:
  extend it (including your own company's domains) through `brands=`.
* The dashboard loads Tailwind from a CDN, so on an air-gapped host it renders unstyled.
  `DEPLOYMENT.md` explains the self-hosted option.
* Free API tiers are small (VirusTotal: 4 requests per minute). The aggregator spends
  that quota on attachment hashes first, then URLs, IPs and domains, and says what it skipped.

## Security notes

* Messages are analysed in memory and never executed or written to disk by this tool.
  (Starlette spools uploads over 1 MiB to a temporary file; the Docker setup mounts
  `/tmp` as RAM-backed tmpfs.)
* Everything from an email is treated as hostile: text is rendered as plain text (never
  HTML or terminal markup), control and direction-override characters are shown escaped,
  and exports are defanged. CSV cells that could run as spreadsheet formulas are neutralised.
* Report weaknesses privately to the maintainers before opening a public issue.

## License

MIT.