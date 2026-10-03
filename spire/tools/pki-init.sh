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

# Demo TLS CA + server certificate for a real PingFederate (docker-compose.pingfederate.yml).
# Stable across PingFederate re-creation, and importable into a browser to avoid warnings.
mkdir -p tls
if [[ ! -f tls/demo-tls-ca.crt ]]; then
  echo "[pki-init] creating demo TLS CA and PingFederate server certificate"
  openssl req -x509 -newkey rsa:2048 -nodes -keyout tls/demo-tls-ca.key -out tls/demo-tls-ca.crt -days 3650 \
    -subj "/O=Agentic AI ICAM Demo/CN=Demo TLS CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"
  openssl req -newkey rsa:2048 -nodes -keyout tls/pingfederate.key -out tls/pingfederate.csr \
    -subj "/O=Agentic AI ICAM Demo/CN=pingfederate"
  cat > tls/pingfederate.ext <<EXT
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:pingfederate,DNS:localhost
EXT
  openssl x509 -req -in tls/pingfederate.csr -CA tls/demo-tls-ca.crt -CAkey tls/demo-tls-ca.key -CAcreateserial \
    -out tls/pingfederate.crt -days 825 -extfile tls/pingfederate.ext
  openssl pkcs12 -export -in tls/pingfederate.crt -inkey tls/pingfederate.key -certfile tls/demo-tls-ca.crt \
    -name runtime-tls -out tls/pingfederate.p12 -passout pass:"${PF_TLS_P12_PASSWORD:-changeit}"
  rm -f tls/pingfederate.csr tls/pingfederate.ext
fi
chmod 0644 tls/demo-tls-ca.crt tls/pingfederate.crt tls/pingfederate.p12
chmod 0600 tls/demo-tls-ca.key tls/pingfederate.key

# spire-server runs as uid 1000 in the upstream image.
chmod 0644 node-ca.crt node-agent.crt
chmod 0600 node-ca.key node-agent.key
chown -R 1000:1000 /spire-server-data /spire-server-socket 2>/dev/null || true
echo "[pki-init] done"
