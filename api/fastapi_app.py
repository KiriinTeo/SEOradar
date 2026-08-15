"""
FUTURE REST API WRAPPER — placeholder / not currently wired into main.py.

This shows exactly how the CLI's core (`run_analysis`) will be exposed
over HTTP once a frontend needs to call it directly, without changing
a single line of the SEO or Security engines — that's the payoff of
keeping `run_analysis()` free of any CLI/argparse/stdout concerns.

To activate this module:
    pip install fastapi "uvicorn[standard]"
    uvicorn api.fastapi_app:app --reload --port 8000

Then:
    GET /health
    POST /analyze              body: {"url": "https://example.com"}
    GET  /analyze?url=https://example.com   (convenience alias)

Left commented-out (rather than deleted) so it's obvious this is a
deliberate, ready-to-uncomment extension point and not dead code.
"""
from __future__ import annotations

# --- Uncomment this whole block once fastapi/uvicorn are installed ---------
#
# from fastapi import FastAPI, HTTPException, Query
# from fastapi.middleware.cors import CORSMiddleware
# from pydantic import BaseModel, Field
#
# from main import run_analysis
# from utils.validators import InvalidURLError
#
# app = FastAPI(
#     title="SEO & Security Analyzer API",
#     version="1.0.0",
#     description="REST wrapper around the SEO Analyzer Engine and "
#                  "Security Analyzer Engine. See core/schema.py for the "
#                  "full response contract.",
# )
#
# # Lock this down to the actual frontend origin(s) before going to production.
# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["*"],
#     allow_methods=["GET", "POST"],
#     allow_headers=["*"],
# )
#
#
# class AnalyzeRequest(BaseModel):
#     url: str = Field(..., examples=["https://example.com"])
#     verify_ssl: bool = True
#
#
# @app.get("/health")
# async def health() -> dict:
#     return {"status": "ok"}
#
#
# @app.post("/analyze")
# async def analyze(payload: AnalyzeRequest) -> dict:
#     try:
#         report = await run_analysis(payload.url, verify_ssl=payload.verify_ssl)
#     except InvalidURLError as e:
#         raise HTTPException(status_code=400, detail=str(e)) from e
#     return report.to_dict()
#
#
# @app.get("/analyze")
# async def analyze_get(url: str = Query(..., description="Target URL to analyze")) -> dict:
#     try:
#         report = await run_analysis(url)
#     except InvalidURLError as e:
#         raise HTTPException(status_code=400, detail=str(e)) from e
#     return report.to_dict()
#
#
# # Production notes for whoever wires this up for real:
# # 1. Add rate limiting (e.g. slowapi) — this tool makes several outbound
# #    requests per call and could be abused as an SSRF/scanning proxy
# #    against arbitrary URLs if left open.
# # 2. Add the private-IP / localhost blocklist in utils/validators.py
# #    before resolving+fetching user-supplied URLs (SSRF hardening) —
# #    a local CLI run doesn't need it, a public HTTP endpoint does.
# # 3. Add a request timeout at the API layer in addition to the
# #    per-request httpx timeout, so a pathological target can't hold
# #    a worker forever.
# # 4. Consider making /analyze async-queued (return a job id, poll for
# #    result) if analyses commonly exceed typical HTTP client timeouts.
# -----------------------------------------------------------------------------
