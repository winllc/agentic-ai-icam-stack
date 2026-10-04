"""Enterprise MCP server (Streamable HTTP transport, JSON responses).

Implements the MCP JSON-RPC methods an agent needs - initialize, tools/list,
tools/call - and enforces OAuth per tool: the delegated token must carry the
scope the tool requires, otherwise HTTP 403 with
WWW-Authenticate: Bearer error="insufficient_scope" (per the MCP authorization spec).
"""

import itertools

from flask import Flask, g, jsonify, request

from icam.common import logs
from icam.common.tokens import TokenError
from icam.resources.auth import audit_view, authorize, log_decision, principal, require_detail, require_system
from icam.resources.data import RUNBOOKS, SYSTEMS, TICKETS
from icam.resources.serve import serve_mtls

log = logs.setup("ops-mcp")
app = Flask(__name__)
REALM = "ops-mcp"
PROTOCOL_VERSION = "2025-06-18"
ticket_seq = itertools.count(1042)

TOOLS = {
    "get_runbook": {
        "scope": "systems:read",
        "description": "Return the operational runbook for a system.",
        "inputSchema": {"type": "object", "properties": {"system": {"type": "string"}}, "required": ["system"]},
    },
    "list_tickets": {
        "scope": "tickets:read",
        "description": "List incident tickets for a system.",
        "inputSchema": {"type": "object", "properties": {"system": {"type": "string"}}, "required": ["system"]},
    },
    "create_ticket": {
        "scope": "tickets:write",
        "description": "Open an incident ticket for a system.",
        "inputSchema": {
            "type": "object",
            "properties": {"system": {"type": "string"}, "title": {"type": "string"},
                           "severity": {"type": "string"}, "details": {"type": "string"}},
            "required": ["system", "title"],
        },
    },
}


def rpc_result(id_, result):
    return jsonify(jsonrpc="2.0", id=id_, result=result)


def rpc_error(id_, code, message):
    return jsonify(jsonrpc="2.0", id=id_, error={"code": code, "message": message})


def text(obj) -> dict:
    import json
    return {"content": [{"type": "text", "text": json.dumps(obj, indent=2)}], "structuredContent": obj}


def call_tool(name: str, args: dict) -> dict:
    claims = g.claims
    system = args.get("system", "")
    if system not in SYSTEMS:
        return {"content": [{"type": "text", "text": f"unknown system {system!r}"}], "isError": True}
    if name == "get_runbook":
        return text({"system": system, "runbook": RUNBOOKS[system]})
    if name == "list_tickets":
        return text({"system": system, "tickets": [t for t in TICKETS if t["system"] == system]})
    if name == "create_ticket":
        ticket = {"id": f"INC-{next(ticket_seq)}", "system": system, "title": args.get("title", ""),
                  "severity": args.get("severity", "medium"), "state": "open",
                  "requested_by": claims["sub"], "created_by_agent": principal()["actor"]}
        TICKETS.append(ticket)
        return text(ticket)
    raise KeyError(name)


@app.post("/mcp")
def mcp():
    msg = request.get_json(force=True, silent=True) or {}
    method, id_, params = msg.get("method"), msg.get("id"), msg.get("params") or {}

    # Every MCP request is authenticated; tools/call additionally needs the tool's scope.
    required = "systems:read"
    if method == "tools/call":
        tool = TOOLS.get(params.get("name"))
        if not tool:
            return rpc_error(id_, -32602, f"unknown tool {params.get('name')!r}")
        required = tool["scope"]
    try:
        g.claims = authorize(required)
        # Task binding (RFC 9396): any MCP use needs a task token; a tool acting on a system
        # needs that system in the token's authorization_details.
        require_detail(g.claims, "system_access")
        system = ((params.get("arguments") or {}).get("system")) if method == "tools/call" else None
        if system:
            require_system(g.claims, system)
    except TokenError as err:
        log_decision(required, None, f"{err.status} {err.error}")
        return err.response(REALM)
    log_decision(required, g.claims, "allowed")

    if method == "initialize":
        return rpc_result(id_, {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "enterprise-ops-mcp", "version": "1.0.0"},
        })
    if method == "notifications/initialized":
        return "", 202
    if method == "tools/list":
        return rpc_result(id_, {"tools": [
            {"name": n, "description": f"{t['description']} (requires scope {t['scope']})",
             "inputSchema": t["inputSchema"]} for n, t in TOOLS.items()]})
    if method == "tools/call":
        return rpc_result(id_, call_tool(params["name"], params.get("arguments") or {}))
    if method == "ping":
        return rpc_result(id_, {})
    return rpc_error(id_, -32601, f"method {method!r} not found")


@app.get("/audit")
def audit():
    return audit_view()


if __name__ == "__main__":
    serve_mtls(app, log)
