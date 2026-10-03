#!/usr/bin/env bash
# Registers the node alias + workload entries with SPIRE Server and publishes
# the trust bundle the SPIRE Agent uses to bootstrap. Idempotent.
set -euo pipefail
SOCK=/tmp/spire-server/private/api.sock
TD=${TRUST_DOMAIN:-demo.local}
NODE_ID="spiffe://${TD}/node/docker-host"
srv() { spire-server "$@" -socketPath "$SOCK"; }

echo "[register] waiting for SPIRE Server"
until srv healthcheck >/dev/null 2>&1; do sleep 1; done

exists() { srv entry show -spiffeID "$1" 2>/dev/null | grep -q "Entry ID"; }

# Node alias: any agent whose x509pop node certificate has CN=docker-host.
if ! exists "$NODE_ID"; then
  srv entry create -node -spiffeID "$NODE_ID" -selector "x509pop:subject:cn:docker-host"
fi

# Workloads: <spiffe path> <docker label value> <dns name>
# The docker WorkloadAttestor resolves the calling PID to a container and
# matches its labels. (Production: also pin docker:image_config_digest.)
while read -r path label dns; do
  [[ -z "$path" || "$path" == \#* ]] && continue
  id="spiffe://${TD}/${path}"
  if exists "$id"; then
    echo "[register] exists: $id"
  else
    srv entry create -parentID "$NODE_ID" -spiffeID "$id" \
      -selector "docker:label:ai.demo.spiffe-workload:${label}" \
      -dns "$dns" -x509SVIDTTL 3600
  fi
done <<'ENTRIES'
idp/pingfederate              pingfederate        pingfederate
agent/analysis-agent          analysis-agent      analysis-agent
agent/remediation-agent       remediation-agent   remediation-agent
resource/systems-api          systems-api         systems-api
resource/ops-mcp              ops-mcp             ops-mcp
ENTRIES

srv bundle show -format pem > /pki/spire-bundle.pem
chmod 0644 /pki/spire-bundle.pem
echo "[register] trust bundle written to /pki/spire-bundle.pem"
srv entry show | grep -E "SPIFFE ID|Selector" || true
