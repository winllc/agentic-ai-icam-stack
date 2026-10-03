"""One agent instance = one OS process spawned by the Agent Runtime per task.

Reads the task (incl. the user's access token) from stdin, then:
  5-7  obtains its own workload identity (X.509-SVID) from the SPIRE Agent
  8-9  exchanges the user's token for a delegated, certificate-bound token at
       PingFederate, authenticating with mTLS using the SVID
  10   calls enterprise resources (REST API + MCP server) over mTLS
and prints a JSON trace of every step on stdout.
"""

import json
import logging
import os
import sys
import tempfile
import time

import requests

from icam.common.spiffe_identity import WorkloadIdentity
from icam.common.tokens import unverified_claims

logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="%(asctime)s [agent-instance] %(message)s")
log = logging.getLogger("agent-instance")

AGENT_NAME = os.environ["AGENT_NAME"]
WORKLOAD_LABEL = os.environ.get("WORKLOAD_LABEL", AGENT_NAME)
DISCOVERY_URL = os.environ["PF_DISCOVERY_URL"]
PF_PUBLIC_BASE = os.environ.get("PF_ISSUER", "").rstrip("/")
PF_INTERNAL_BASE = os.environ.get("PF_INTERNAL_BASE", "").rstrip("/")
PF_TLS_CA = os.environ.get("PF_TLS_CA")  # None -> trust the SPIFFE bundle (demo AS is a SPIFFE workload)
SYSTEMS_API = os.environ.get("SYSTEMS_API_URL", "https://systems-api:8443")
OPS_MCP = os.environ.get("OPS_MCP_URL", "https://ops-mcp:8443/mcp")
TASK_SCOPES = os.environ.get("TASK_SCOPES",
                             "systems:read systems:analyze metrics:read tickets:read tickets:write")
TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
TT_ACCESS = "urn:ietf:params:oauth:token-type:access_token"


class Trace:
    def __init__(self):
        self.steps = []

    def add(self, n, title, actor, status="ok", **detail):
        self.steps.append({"n": n, "title": title, "actor": actor, "status": status, "detail": detail})
        log.info("step %s %s [%s]", n, title, status)


def backchannel(url: str) -> str:
    """Discovery advertises browser-facing URLs; containers reach the AS by service name."""
    if PF_PUBLIC_BASE and PF_INTERNAL_BASE and url.startswith(PF_PUBLIC_BASE):
        return PF_INTERNAL_BASE + url[len(PF_PUBLIC_BASE):]
    return url


def run(job: dict) -> dict:
    trace = Trace()
    system = job["system"]
    result = {"task_id": job["task_id"], "agent": AGENT_NAME, "pid": os.getpid(), "system": system}

    # ---- 5-7: workload identity from SPIRE ------------------------------------------
    identity = WorkloadIdentity(workdir=tempfile.mkdtemp(prefix="agent-svid-"))
    started = time.time()
    try:
        info = identity.wait_for_svid(attempts=5, delay=1)
    except Exception as exc:
        trace.add(5, "Workload API call failed", "Agent instance → SPIRE Agent", "error", error=str(exc))
        return {**result, "steps": trace.steps, "error": "no workload identity"}
    trace.add(5, "Workload API: FetchX509SVID", "Agent instance → SPIRE Agent",
              socket=identity.socket_path, caller_pid=os.getpid(),
              note="No secret was provisioned to the agent - it only proves *what it is* to the local SPIRE Agent.")
    trace.add(6, "Workload attested & selectors verified", "SPIRE Agent ↔ SPIRE Server",
              workload_attestor="docker (PID → container → labels)",
              matched_selector=f"docker:label:ai.demo.spiffe-workload:{WORKLOAD_LABEL}",
              node_identity="spiffe://demo.local/node/docker-host (x509pop node attestation)",
              assigned_spiffe_id=info["spiffe_id"], elapsed_ms=int((time.time() - started) * 1000))
    trace.add(7, "X.509-SVID issued", "SPIRE → AI Agent", **info)
    result["svid"] = info

    # ---- 8-9: OAuth token exchange with mTLS client authentication ---------------------
    disco = requests.get(DISCOVERY_URL, timeout=10, verify=PF_TLS_CA or True).json()
    token_ep = os.environ.get("PF_MTLS_TOKEN_ENDPOINT") or backchannel(
        disco.get("mtls_endpoint_aliases", {}).get("token_endpoint") or disco["token_endpoint"])
    resources = [SYSTEMS_API, OPS_MCP]
    form = {
        "grant_type": TOKEN_EXCHANGE,
        "client_id": AGENT_NAME,
        "subject_token": job["user_token"],
        "subject_token_type": TT_ACCESS,
        "requested_token_type": TT_ACCESS,
        "scope": TASK_SCOPES,
        "resource": resources,
    }
    resp = requests.post(token_ep, data=form, cert=identity.client_cert,
                         verify=PF_TLS_CA or str(identity.bundle_path), timeout=15)
    body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
    trace.add(8, "OAuth 2.0 Token Exchange (RFC 8693) + mTLS client auth (RFC 8705)", "AI Agent → PingFederate",
              "ok" if resp.ok else "denied",
              token_endpoint=token_ep, client_id=AGENT_NAME, client_certificate=info["spiffe_id"],
              subject_token="user access token (sub=%s)" % unverified_claims(job["user_token"]).get("sub"),
              requested_scope=TASK_SCOPES, resource=resources, http_status=resp.status_code)
    if not resp.ok:
        trace.add(9, "Token exchange rejected", "PingFederate", "denied", **body)
        return {**result, "steps": trace.steps, "error": body.get("error_description", "token exchange failed")}

    delegated = body["access_token"]
    claims = unverified_claims(delegated)
    trace.add(9, "Delegated token issued: User ∩ Agent ∩ Requested", "PingFederate → AI Agent",
              granted_scope=body.get("scope"), policy_evaluation=body.get("demo_policy_evaluation"),
              claims=claims)
    result["delegated_token"] = {"claims": claims, "jwt": delegated}

    # ---- 10: enterprise resources over mTLS with the bound token -----------------------
    session = requests.Session()
    session.cert = identity.client_cert
    session.verify = str(identity.bundle_path)
    session.headers["Authorization"] = f"Bearer {delegated}"
    calls, data = [], {}

    def record(kind, op, scope, r):
        entry = {"kind": kind, "operation": op, "scope": scope, "http_status": r.status_code,
                 "outcome": "allowed" if r.ok else (r.headers.get("WWW-Authenticate") or r.text[:200])}
        calls.append(entry)
        return entry

    def rest(method, path, scope, key):
        r = session.request(method, f"{SYSTEMS_API}{path}", timeout=10)
        record("REST", f"{method} {path}", scope, r)
        if r.ok:
            data[key] = r.json()

    rest("GET", f"/systems/{system}", "systems:read", "system")
    rest("GET", f"/systems/{system}/metrics", "metrics:read", "metrics")
    rest("POST", f"/systems/{system}/diagnostics", "systems:analyze", "diagnostics")

    mcp_ids = iter(range(1, 100))
    mcp_headers = {"Accept": "application/json, text/event-stream", "MCP-Protocol-Version": "2025-06-18"}

    def mcp(method, params=None, scope="systems:read", label=None):
        msg = {"jsonrpc": "2.0", "method": method, "params": params or {}}
        if not method.startswith("notifications/"):
            msg["id"] = next(mcp_ids)
        r = session.post(OPS_MCP, json=msg, headers=mcp_headers, timeout=10)
        record("MCP", label or method, scope, r)
        return r.json().get("result") if r.ok and r.content else None

    init = mcp("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                              "clientInfo": {"name": AGENT_NAME, "version": "1.0"}})
    if init is not None:
        mcp("notifications/initialized")
        tools = mcp("tools/list") or {}
        data["mcp_tools"] = [t["name"] for t in tools.get("tools", [])]
        for tool, scope in (("get_runbook", "systems:read"), ("list_tickets", "tickets:read")):
            out = mcp("tools/call", {"name": tool, "arguments": {"system": system}}, scope, f"tools/call {tool}")
            if out:
                data[tool] = out.get("structuredContent")

    findings = analyze(system, data)
    if findings["severity"] in ("high", "critical"):
        out = mcp("tools/call", {"name": "create_ticket", "arguments": {
            "system": system, "severity": findings["severity"],
            "title": f"[{AGENT_NAME}] {findings['headline']}",
            "details": "; ".join(findings["issues"])}}, "tickets:write", "tools/call create_ticket")
        if out:
            data["ticket"] = out.get("structuredContent")

    denied = [c for c in calls if c["http_status"] in (401, 403)]
    trace.add(10, "API / MCP calls to enterprise resources", "AI Agent → Enterprise Resources",
              "partial" if denied else "ok", calls=calls,
              note="Each call: mTLS with the SVID + bearer token bound to that SVID (cnf.x5t#S256).")

    result["data"] = data
    result["findings"] = findings
    result["summary"] = summarize(job["task"], system, data, findings, calls)
    result["steps"] = trace.steps
    return result


def analyze(system: str, data: dict) -> dict:
    issues, severity = [], "ok"
    rank = ["ok", "low", "medium", "high", "critical"]
    for d in (data.get("diagnostics") or {}).get("diagnostics", []):
        if d["severity"] != "ok":
            issues.append(f"{d['check']}: {d['result']} ({d['severity']})")
            severity = max(severity, d["severity"], key=rank.index)
    m = (data.get("metrics") or {}).get("metrics", {})
    if m.get("error_rate_pct", 0) > 2:
        issues.append(f"error rate {m['error_rate_pct']}% above 2% SLO")
        severity = max(severity, "high", key=rank.index)
    if m.get("p99_latency_ms", 0) > 1000:
        issues.append(f"p99 latency {m['p99_latency_ms']} ms above 1000 ms SLO")
        severity = max(severity, "medium", key=rank.index)
    status = (data.get("system") or {}).get("status")
    if status and status != "healthy":
        issues.insert(0, f"system status is {status}")
        severity = max(severity, "high", key=rank.index)
    headline = f"{system}: {issues[0]}" if issues else f"{system}: no issues found"
    blind_spots = [k for k in ("system", "metrics", "diagnostics") if k not in data]
    return {"severity": severity, "issues": issues, "headline": headline, "not_visible": blind_spots}


def summarize(task: str, system: str, data: dict, findings: dict, calls: list) -> dict:
    """Rule-based summary; optionally enriched by Claude when ANTHROPIC_API_KEY is set."""
    lines = [f"Task: {task}", f"Overall severity: {findings['severity'].upper()}"]
    lines += [f"- {i}" for i in findings["issues"]] or ["- No issues found in the data the agent was allowed to see."]
    if findings["not_visible"]:
        lines.append(f"Not visible with delegated scope: {', '.join(findings['not_visible'])}")
    if "ticket" in data:
        lines.append(f"Opened ticket {data['ticket']['id']}.")
    elif findings["severity"] in ("high", "critical"):
        lines.append("Wanted to open a ticket but the delegated token lacks tickets:write.")
    summary = {"engine": "rules", "text": "\n".join(lines)}

    if not os.environ.get("ANTHROPIC_API_KEY"):
        return summary
    try:
        import anthropic

        client = anthropic.Anthropic()
        prompt = (
            "You are an SRE analysis agent acting on behalf of a user with a delegated, scope-limited token. "
            "Write a concise operational assessment (under 150 words) of the system below. Mention any data "
            "you could not see because of authorization limits.\n\n"
            f"Task: {task}\nSystem: {system}\n"
            f"Data: {json.dumps(data, default=str)}\n"
            f"Calls: {json.dumps(calls)}"
        )
        msg = client.beta.messages.create(
            model=os.environ.get("ANTHROPIC_MODEL", "claude-opus-5-5"),
            max_tokens=16000,
            output_config={"effort": "low"},
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",
            messages=[{"role": "user", "content": prompt}],
        )
        if msg.stop_reason == "refusal":
            return {**summary, "llm_note": "model declined; showing rule-based summary"}
        text = "".join(b.text for b in msg.content if b.type == "text").strip()
        return {"engine": f"claude ({msg.model})", "text": text, "rules": summary["text"]}
    except Exception as exc:  # the demo must work offline
        log.warning("Claude summary failed: %s", exc)
        return {**summary, "llm_note": f"Claude unavailable: {exc}"}


if __name__ == "__main__":
    job = json.load(sys.stdin)
    try:
        out = run(job)
    except Exception as exc:
        log.exception("agent instance failed")
        out = {"task_id": job.get("task_id"), "agent": AGENT_NAME, "error": str(exc), "steps": []}
    json.dump(out, sys.stdout)
