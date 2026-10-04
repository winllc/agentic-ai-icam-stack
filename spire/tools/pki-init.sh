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

# --- Demo enterprise PKI (stands in for an organisation's approved CA hierarchy) ---------
#   Demo Enterprise Root CA
#     ├─ Demo Enterprise SPIRE Issuing CA  -> SPIRE UpstreamAuthority: SPIRE's CA is chained
#     │                                       below it, so SVIDs validate against the root
#     └─ Demo Enterprise TLS Issuing CA    -> PingFederate's runtime HTTPS certificate
# One trust anchor (the root) for browsers, legacy systems, PingFederate and partners.
mkdir -p enterprise
E=enterprise
ca_ext='basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid'
if [[ ! -f $E/root-ca.crt ]]; then
  echo "[pki-init] creating demo enterprise root CA"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-384 -nodes -keyout $E/root-ca.key -out $E/root-ca.crt \
    -days 7300 -subj "/C=US/O=Agentic AI ICAM Demo/OU=Enterprise PKI/CN=Demo Enterprise Root CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"
fi
issuing_ca() {   # issuing_ca <name> <CN>
  local n=$1 cn=$2
  [[ -f $E/$n.crt ]] && return
  echo "[pki-init] issuing $cn"
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-384 -nodes -keyout $E/$n.key -out $E/$n.csr \
    -subj "/C=US/O=Agentic AI ICAM Demo/OU=Enterprise PKI/CN=$cn"
  printf "$ca_ext\n" > $E/$n.ext
  openssl x509 -req -in $E/$n.csr -CA $E/root-ca.crt -CAkey $E/root-ca.key -CAcreateserial \
    -out $E/$n.crt -days 1825 -extfile $E/$n.ext
  rm -f $E/$n.csr $E/$n.ext
}
issuing_ca spire-issuing-ca "Demo Enterprise SPIRE Issuing CA"
issuing_ca tls-issuing-ca "Demo Enterprise TLS Issuing CA"

mkdir -p tls
if [[ ! -f tls/pingfederate.p12 ]]; then
  echo "[pki-init] issuing PingFederate server certificate (TLS issuing CA)"
  openssl req -newkey rsa:2048 -nodes -keyout tls/pingfederate.key -out tls/pingfederate.csr \
    -subj "/C=US/O=Agentic AI ICAM Demo/CN=pingfederate"
  printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:pingfederate,DNS:localhost\n' > tls/pingfederate.ext
  openssl x509 -req -in tls/pingfederate.csr -CA $E/tls-issuing-ca.crt -CAkey $E/tls-issuing-ca.key \
    -CAcreateserial -out tls/pingfederate.crt -days 825 -extfile tls/pingfederate.ext
  cat $E/tls-issuing-ca.crt > tls/pingfederate-chain.crt
  openssl pkcs12 -export -in tls/pingfederate.crt -inkey tls/pingfederate.key -certfile tls/pingfederate-chain.crt \
    -name runtime-tls -out tls/pingfederate.p12 -passout pass:"${PF_TLS_P12_PASSWORD:-changeit}"
  rm -f tls/pingfederate.csr tls/pingfederate.ext
fi
cp $E/root-ca.crt tls/trust-anchor.pem                 # what clients of PingFederate trust
chmod 0644 $E/*.crt tls/*.crt tls/*.pem tls/pingfederate.p12
chmod 0600 $E/*.key tls/pingfederate.key
# SPIRE Server (uid 1000) signs its CA with the SPIRE issuing CA key.
chown 1000:1000 $E/spire-issuing-ca.key && chmod 0400 $E/spire-issuing-ca.key

# spire-server runs as uid 1000 in the upstream image.
chown -R 1000:1000 /spire-server-data /spire-server-socket \
  /partner-server-data /partner-server-socket 2>/dev/null || true
echo "[pki-init] done"
