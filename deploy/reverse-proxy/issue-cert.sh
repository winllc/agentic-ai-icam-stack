#!/usr/bin/env bash
# Issues the reverse proxy's certificate for the public host names (demo enterprise TLS issuing CA).
set -euo pipefail
host() { printf '%s' "$1" | sed -E 's#^[a-z]+://##; s#[/:].*$##'; }
portal=$(host "$PORTAL_PUBLIC_URL"); pf=$(host "$PF_PUBLIC_URL")
san="DNS:$portal,DNS:$pf"
E=/pki/enterprise; T=/pki/proxy
mkdir -p $T
if [[ -f $T/proxy.crt && "$(cat $T/proxy.san 2>/dev/null)" == "$san" ]] &&
   openssl verify -CAfile $E/root-ca.crt -untrusted $E/tls-issuing-ca.crt $T/proxy.crt >/dev/null 2>&1; then
  echo "[proxy-cert] certificate for $san is current"; exit 0
fi
echo "[proxy-cert] issuing reverse-proxy certificate for $san"
openssl req -newkey rsa:2048 -nodes -keyout $T/proxy.key -out $T/proxy.csr -subj "/C=US/O=Agentic AI ICAM Demo/CN=$portal"
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=%s\n' "$san" > $T/proxy.ext
openssl x509 -req -in $T/proxy.csr -CA $E/tls-issuing-ca.crt -CAkey $E/tls-issuing-ca.key -CAcreateserial \
  -out $T/proxy.crt -days 825 -extfile $T/proxy.ext
cat $T/proxy.crt $E/tls-issuing-ca.crt > $T/proxy-fullchain.crt
printf '%s' "$san" > $T/proxy.san
rm -f $T/proxy.csr $T/proxy.ext
chmod 0644 $T/proxy-fullchain.crt; chmod 0640 $T/proxy.key; chgrp 101 $T/proxy.key   # nginx group
