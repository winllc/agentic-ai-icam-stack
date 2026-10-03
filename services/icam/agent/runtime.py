"""Agent Runtime: accepts tasks from the Agentic AI Service and runs each one in a
fresh agent-instance process. The runtime checks the user's token; the instance
obtains its own workload identity and delegated token."""

import json
import os
import subprocess
import sys
import time
import uuid

from flask import Flask, jsonify, request

from icam.common import logs
from icam.common.tokens import JwtValidator, TokenError, bearer_token, scopes_of

log = logs.setup(os.environ.get("AGENT_NAME", "agent-runtime"))
app = Flask(__name__)
validator = JwtValidator(os.environ["PF_JWKS_URL"], os.environ["PF_ISSUER"])
USER_TOKEN_AUDIENCE = os.environ.get("USER_TOKEN_AUDIENCE", "agentic-ai-service")


@app.post("/tasks")
def submit_task():
    try:
        token = bearer_token(request)
        user = validator.validate(token, audience=USER_TOKEN_AUDIENCE)
    except TokenError as err:
        return err.response("agent-runtime")

    body = request.get_json(force=True)
    job = {"task_id": uuid.uuid4().hex[:12], "task": body.get("task", ""),
           "system": body.get("system", ""), "user_token": token}
    started = time.time()
    proc = subprocess.run([sys.executable, "-m", "icam.agent.instance"], input=json.dumps(job),
                          capture_output=True, text=True, timeout=180)
    for line in proc.stderr.splitlines():
        log.info("[instance %s] %s", job["task_id"], line)
    try:
        result = json.loads(proc.stdout)
    except json.JSONDecodeError:
        result = {"task_id": job["task_id"], "error": "agent instance crashed", "stderr": proc.stderr[-2000:],
                  "steps": []}

    result["steps"].insert(0, {
        "n": 4, "title": "Task handed to Agent Runtime → new Agent Instance", "actor": "Agentic AI Service → Agent Runtime",
        "status": "ok",
        "detail": {"task": job["task"], "system": job["system"], "user": user["sub"],
                   "user_token_scope": " ".join(sorted(scopes_of(user))), "runtime": os.environ.get("AGENT_NAME"),
                   "agent_instance_pid": result.get("pid"),
                   "note": "The runtime validated the user's token (signature, issuer, audience) before spawning."},
    })
    result["elapsed_ms"] = int((time.time() - started) * 1000)
    return jsonify(result)


@app.get("/healthz")
def healthz():
    return "ok"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8090, threaded=True)
