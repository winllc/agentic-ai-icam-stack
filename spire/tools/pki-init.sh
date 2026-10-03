#!/usr/bin/env bash
# Generates the node-attestation PKI used by the x509pop NodeAttestor.
# Idempotent: existing material is kept across restarts.
set -euo pipefail
PKI=/pki
mkdir -p "$PKI"
cd "$PKI"

if [[ ! -f node-ca.crt ]]; then
  echo "[pki-init] creating node CA"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout node-ca.key -out node-ca.crt -days 3650 \
    -subj "/O=Agentic AI ICAM Demo/CN=Demo Node CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"
fi

if [[ ! -f node-agent.crt ]]; then
  echo "[pki-init] issuing node certificate for the SPIRE agent host"
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout node-agent.key -out node-agent.csr -subj "/O=Agentic AI ICAM Demo/CN=docker-host"
  cat > node-agent.ext <<EXT
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
EXT
  openssl x509 -req -in node-agent.csr -CA node-ca.crt -CAkey node-ca.key -CAcreateserial \
    -out node-agent.crt -days 825 -extfile node-agent.ext
  rm -f node-agent.csr node-agent.ext
fi

# spire-server runs as uid 1000 in the upstream image.
chmod 0644 node-ca.crt node-agent.crt
chmod 0600 node-ca.key node-agent.key
chown -R 1000:1000 /spire-server-data /spire-server-socket 2>/dev/null || true
echo "[pki-init] done"
