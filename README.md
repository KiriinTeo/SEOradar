# SEO & Security Analyzer

A CLI tool that passively audits a URL's on-page SEO and HTTP/TLS security
posture, and emits a single structured JSON report designed to be the stable
API contract for a future frontend.

## Install

```bash
pip install -r requirements.txt
```

## Run

```bash
python main.py https://example.com
python main.py https://example.com --pretty              # pretty-printed JSON
python main.py https://example.com --output report.json  # also write to file
python main.py https://example.com --quiet                # suppress log lines on stderr
python main.py https://example.com --insecure             # skip TLS verification on the fetch itself
```

Exit code is `0` on a clean/warning report, `1` on an internal error, `2` on
an invalid URL. The JSON report is always printed on stdout regardless of
exit code — even total failures produce a valid, schema-shaped payload with
`fatal_error` or per-section `error` fields set.

## Architecture

```
seo_security_analyzer/
├── main.py                 # CLI entry point / orchestrator only — no analysis logic
├── core/
│   ├── http_client.py      # Shared async fetch wrapper: timing, redirects, error normalization
│   ├── schema.py            # Dataclasses defining the stable JSON contract
│   └── scorer.py            # Scoring/grading rubric, decoupled from extraction logic
├── engines/
│   ├── seo_engine.py        # SEO Analyzer Engine (independent, testable in isolation)
│   └── security_engine.py   # Security Analyzer Engine (independent, passive-only)
├── utils/
│   ├── logger.py
│   └── validators.py
└── api/
    └── fastapi_app.py       # Commented-out placeholder for the future REST wrapper
```

- **Modular engines.** `SEOAnalyzer` and `SecurityAnalyzer` share nothing but
  the `HttpClient`. Either can be swapped, unit-tested, or rewritten without
  touching the other.
- **`run_analysis()` in `main.py`** is the reusable core — CLI-agnostic,
  `async def run_analysis(url: str) -> AnalysisReport`. This is exactly what
  `api/fastapi_app.py` calls once uncommented; the REST layer adds zero new
  analysis code.
- **Resilience.** Every network call goes through `HttpClient.get()`, which
  never raises — connect errors, timeouts, and redirect loops all become a
  `FetchResult(ok=False, error=...)`. Each engine method further wraps its
  own parsing so one broken check (e.g. malformed sitemap XML) can't take
  down the rest of the report. `_safe_run()` in `main.py` is the last line
  of defense if an engine still manages to raise.

## Security Engine scope

Passive audit only: TLS certificate inspection and reading the response
headers/cookies from a normal GET request. It does **not** perform payload
injection, fuzzing, port scanning, or auth bypass attempts — this keeps it
safe to run against third-party sites without separate authorization.

## Extending to a REST API

See `api/fastapi_app.py`. Uncomment, `pip install fastapi "uvicorn[standard]"`,
run `uvicorn api.fastapi_app:app --reload`. Before exposing this publicly,
read the "Production notes" comment block at the bottom of that file — in
particular, add SSRF hardening (block private/loopback IP targets) since a
public HTTP endpoint that fetches arbitrary user-supplied URLs is a classic
SSRF vector that a local CLI tool doesn't need to worry about.

## Example output

See `example_output.json` for a full sample report from a successful run.
