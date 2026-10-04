#!/usr/bin/env bash
# Generates the node-attestation PKI used by the x509pop NodeAttestor.
# Idempotent: existing material is kept across restarts.
set -euo pipefail
PKI=/pki
mkdir -p "$PKI"
cd "$PKI"

# node_pki <prefix> <CN>: a node CA and one node certificate for x509pop node attestation.
node_pki() {
  local p=$1 cn=$2
  if [[ ! -f $p-ca.crt ]]; then
    echo "[pki-init] creating $p CA"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
      -keyout $p-ca.key -out $p-ca.crt -days 3650 \
      -subj "/O=Agentic AI ICAM Demo/CN=Demo ${p} CA" \
      -addext "basicConstraints=critical,CA:TRUE" \
      -addext "keyUsage=critical,keyCertSign,cRLSign"
  fi
  if [[ ! -f $p-agent.crt ]]; then
    echo "[pki-init] issuing $p certificate CN=$cn for its SPIRE agent"
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
      -keyout $p-agent.key -out $p-agent.csr -subj "/O=Agentic AI ICAM Demo/CN=$cn"
    printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n' > $p-agent.ext
    openssl x509 -req -in $p-agent.csr -CA $p-ca.crt -CAkey $p-ca.key -CAcreateserial \
      -out $p-agent.crt -days 825 -extfile $p-agent.ext
    rm -f $p-agent.csr $p-agent.ext
  fi
  chmod 0644 $p-ca.crt $p-agent.crt
  chmod 0600 $p-ca.key $p-agent.key
}
node_pki node docker-host            # trust domain demo.local
node_pki partner-node partner-host   # trust domain partner.example (the external partner)

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
chown -R 1000:1000 /spire-server-data /spire-server-socket \
  /partner-server-data /partner-server-socket 2>/dev/null || true
echo "[pki-init] done"
