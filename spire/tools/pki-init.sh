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
#   Demo Enterprise Root CA        (offline in real life; its key signs only issuing CAs)
#     ├─ Demo Enterprise SPIRE Issuing CA  -> key generated INSIDE Vault (pki_spire mount);
#     │                                       vault-init signs Vault's CSR with this root.
#     │                                       SPIRE's UpstreamAuthority "vault" chains SPIRE's
#     │                                       CA below it, so SVIDs validate against the root.
#     └─ Demo Enterprise TLS Issuing CA    -> PingFederate's and Vault's HTTPS certificates
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
# chains <cert> <untrusted-chain-or-empty>: does it still verify against the current root?
chains() { openssl verify -CAfile $E/root-ca.crt ${2:+-untrusted $2} "$1" >/dev/null 2>&1; }
issuing_ca() {   # issuing_ca <name> <CN>
  local n=$1 cn=$2
  if [[ -f $E/$n.crt ]] && chains $E/$n.crt; then return; fi
  echo "[pki-init] issuing $cn"
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-384 -nodes -keyout $E/$n.key -out $E/$n.csr \
    -subj "/C=US/O=Agentic AI ICAM Demo/OU=Enterprise PKI/CN=$cn"
  printf "$ca_ext\n" > $E/$n.ext
  openssl x509 -req -in $E/$n.csr -CA $E/root-ca.crt -CAkey $E/root-ca.key -CAcreateserial \
    -out $E/$n.crt -days 1825 -extfile $E/$n.ext
  rm -f $E/$n.csr $E/$n.ext
}
issuing_ca tls-issuing-ca "Demo Enterprise TLS Issuing CA"

mkdir -p tls
# PingFederate's names: the container name, localhost, the host of PF_PUBLIC_URL and PF_TLS_EXTRA_SANS
# (comma-separated, e.g. "DNS:sso.example.com,IP:10.0.0.5").
pf_host=$(printf '%s' "${PF_PUBLIC_URL:-}" | sed -E 's#^[a-z]+://##; s#[/:].*$##')
pf_san="DNS:pingfederate,DNS:localhost"
if [[ -n $pf_host && $pf_host != localhost && $pf_host != pingfederate ]]; then
  if [[ $pf_host =~ ^[0-9.]+$ ]]; then pf_san+=",IP:$pf_host"; else pf_san+=",DNS:$pf_host"; fi
fi
[[ -n ${PF_TLS_EXTRA_SANS:-} ]] && pf_san+=",${PF_TLS_EXTRA_SANS// /}"
if [[ -f tls/pingfederate.crt ]] && ! chains tls/pingfederate.crt $E/tls-issuing-ca.crt; then
  echo "[pki-init] PingFederate certificate does not chain to the current root (older volume) - re-issuing"
  rm -f tls/pingfederate.p12 tls/pingfederate.crt tls/pingfederate.key
elif [[ -f tls/pingfederate.crt && "$(cat tls/pingfederate.san 2>/dev/null)" != "$pf_san" ]]; then
  echo "[pki-init] PingFederate host names changed ($pf_san) - re-issuing"
  rm -f tls/pingfederate.p12 tls/pingfederate.crt tls/pingfederate.key
fi
if [[ ! -f tls/pingfederate.p12 ]]; then
  echo "[pki-init] issuing PingFederate server certificate (TLS issuing CA)"
  openssl req -newkey rsa:2048 -nodes -keyout tls/pingfederate.key -out tls/pingfederate.csr \
    -subj "/C=US/O=Agentic AI ICAM Demo/CN=pingfederate"
  printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=%s\n' "$pf_san" > tls/pingfederate.ext
  openssl x509 -req -in tls/pingfederate.csr -CA $E/tls-issuing-ca.crt -CAkey $E/tls-issuing-ca.key \
    -CAcreateserial -out tls/pingfederate.crt -days 825 -extfile tls/pingfederate.ext
  cat $E/tls-issuing-ca.crt > tls/pingfederate-chain.crt
  openssl pkcs12 -export -in tls/pingfederate.crt -inkey tls/pingfederate.key -certfile tls/pingfederate-chain.crt \
    -name runtime-tls -out tls/pingfederate.p12 -passout pass:"${PF_TLS_P12_PASSWORD:-changeit}"
  rm -f tls/pingfederate.csr tls/pingfederate.ext
  printf '%s' "$pf_san" > tls/pingfederate.san
fi
server_cert() {   # server_cert <name> <SAN list> - issued by the TLS issuing CA, with chain
  local n=$1 san=$2
  if [[ -f tls/$n.crt ]] && chains tls/$n.crt $E/tls-issuing-ca.crt; then return; fi
  echo "[pki-init] issuing $n server certificate (TLS issuing CA)"
  openssl req -newkey rsa:2048 -nodes -keyout tls/$n.key -out tls/$n.csr -subj "/C=US/O=Agentic AI ICAM Demo/CN=$n"
  printf "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=$san\n" > tls/$n.ext
  openssl x509 -req -in tls/$n.csr -CA $E/tls-issuing-ca.crt -CAkey $E/tls-issuing-ca.key -CAcreateserial \
    -out tls/$n.crt -days 825 -extfile tls/$n.ext
  cat tls/$n.crt $E/tls-issuing-ca.crt > tls/$n-fullchain.crt
  rm -f tls/$n.csr tls/$n.ext
}
server_cert vault "DNS:vault,DNS:localhost"

cp $E/root-ca.crt tls/trust-anchor.pem                 # what clients of PingFederate / Vault trust
chmod 0644 $E/*.crt tls/*.crt tls/*.pem tls/pingfederate.p12
chmod 0600 $E/*.key tls/pingfederate.key
# Vault (uid 100 in the official image) reads its TLS key.
chown 100:1000 tls/vault.key && chmod 0440 tls/vault.key
chmod 0644 tls/vault-fullchain.crt

# spire-server runs as uid 1000 in the upstream image.
chown -R 1000:1000 /spire-server-data /spire-server-socket \
  /partner-server-data /partner-server-socket 2>/dev/null || true
echo "[pki-init] done"
