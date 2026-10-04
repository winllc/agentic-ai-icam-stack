#!/usr/bin/env bash
# Federates the two SPIRE trust domains, registers node aliases + workload entries in
# both, and publishes the trust bundles the SPIRE Agents bootstrap from. Idempotent.
set -euo pipefail
TD=${TRUST_DOMAIN:-demo.local}
PTD=${PARTNER_TRUST_DOMAIN:-partner.example}
DEMO_SOCK=/tmp/spire-server/private/api.sock
PARTNER_SOCK=/tmp/spire-server-partner/private/api.sock

srv() { local sock=$1; shift; spire-server "$@" -socketPath "$sock"; }

for sock in "$DEMO_SOCK" "$PARTNER_SOCK"; do
  echo "[register] waiting for SPIRE Server at $sock"
  until srv "$sock" healthcheck >/dev/null 2>&1; do sleep 1; done
done

# --- SPIFFE federation bootstrap: hand each server the other's bundle once; afterwards
# each keeps it current from the other's bundle endpoint (https_spiffe profile).
srv "$DEMO_SOCK" bundle show -format spiffe > /tmp/demo.bundle
srv "$PARTNER_SOCK" bundle show -format spiffe > /tmp/partner.bundle
srv "$DEMO_SOCK" bundle set -id "spiffe://$PTD" -format spiffe -path /tmp/partner.bundle
srv "$PARTNER_SOCK" bundle set -id "spiffe://$TD" -format spiffe -path /tmp/demo.bundle
echo "[register] federated $TD <-> $PTD"

# Capture first: `cmd | grep -q` under pipefail fails when grep exits early (SIGPIPE).
show() { srv "$1" entry show -spiffeID "$2" 2>/dev/null || true; }

# ensure <socket> <spiffe id> <create args...>
# Creates the entry, or re-creates it when its federation set differs from the desired one.
ensure() {
  local sock=$1 id=$2; shift 2
  local want_fed="" out entry_id
  for ((i = 1; i <= $#; i++)); do
    # `entry show` prints federated trust domains without the spiffe:// prefix
    [[ "${!i}" == "-federatesWith" ]] && { j=$((i + 1)); want_fed+="${!j#spiffe://} "; }
  done
  out=$(show "$sock" "$id")
  if [[ "$out" == *"Entry ID"* ]]; then
    local have_fed
    have_fed=$(grep -E "^FederatesWith" <<<"$out" | awk '{print $NF}' | sort | tr '\n' ' ' || true)
    want_fed=$(tr ' ' '\n' <<<"$want_fed" | grep -v '^$' | sort | tr '\n' ' ' || true)
    if [[ "$have_fed" == "$want_fed" ]]; then
      echo "[register] exists: $id"
      return
    fi
    entry_id=$(grep -E "^Entry ID" <<<"$out" | awk '{print $NF}' | head -1)
    echo "[register] updating federation of $id"
    srv "$sock" entry delete -entryID "$entry_id" >/dev/null
  fi
  if ! out=$(srv "$sock" entry create -spiffeID "$id" "$@" 2>&1); then
    [[ "$out" == *AlreadyExists* ]] || { echo "$out"; return 1; }
  fi
  echo "[register] created: $id"
}

# --- demo.local: node alias + infrastructure workloads (docker WorkloadAttestor matches
# container labels; production would also pin docker:image_config_digest). Agent entries are
# NOT registered here: directory-sync owns them, driven by the LDAP directory (ou=agents).
NODE_ID="spiffe://$TD/node/docker-host"
ensure "$DEMO_SOCK" "$NODE_ID" -node -selector "x509pop:subject:cn:docker-host"
while read -r path label dns fed; do
  [[ -z "$path" || "$path" == \#* ]] && continue
  args=(-parentID "$NODE_ID" -selector "docker:label:ai.demo.spiffe-workload:$label" -dns "$dns" -x509SVIDTTL 3600)
  [[ "$fed" == "federated" ]] && args+=(-federatesWith "spiffe://$PTD")
  ensure "$DEMO_SOCK" "spiffe://$TD/$path" "${args[@]}"
done <<'ENTRIES'
idp/pingfederate              pingfederate        pingfederate        -
resource/systems-api          systems-api         systems-api         -
resource/ops-mcp              ops-mcp             ops-mcp             -
ops/pf-configurator           pf-configurator     pf-configurator     -
ENTRIES

# --- partner.example: the external organisation's workloads trust demo.local agents.
PNODE_ID="spiffe://$PTD/node/partner-host"
ensure "$PARTNER_SOCK" "$PNODE_ID" -node -selector "x509pop:subject:cn:partner-host"
while read -r path label dns; do
  [[ -z "$path" || "$path" == \#* ]] && continue
  ensure "$PARTNER_SOCK" "spiffe://$PTD/$path" -parentID "$PNODE_ID" \
    -selector "docker:label:example.partner.spiffe-workload:$label" -dns "$dns" -x509SVIDTTL 3600 \
    -federatesWith "spiffe://$TD"
done <<'ENTRIES'
authz/partner-as              partner-as          partner-as
api/partner-api               partner-api         partner-api
ENTRIES

srv "$DEMO_SOCK" bundle show -format pem > /pki/spire-bundle.pem
srv "$PARTNER_SOCK" bundle show -format pem > /pki/partner-bundle.pem
chmod 0644 /pki/spire-bundle.pem /pki/partner-bundle.pem
echo "[register] trust bundles written to /pki"
