#!/bin/sh
# Renders nginx.conf.template from the public URLs and the TLS mode, then runs nginx.
set -eu
host() { printf '%s' "$1" | sed -E 's#^[a-z]+://##; s#[/:].*$##'; }
scheme() { case "$1" in https://*) echo https ;; *) echo http ;; esac; }
export PORTAL_HOST="$(host "$PORTAL_PUBLIC_URL")" PF_HOST="$(host "$PF_PUBLIC_URL")"
if [ "${PROXY_TLS:-true}" = false ]; then
  # A third-party proxy terminates TLS and forwards plain HTTP here. The scheme browsers use
  # comes from the configured public URL, not from a client-supplied header.
  export LISTEN="80" PUBLIC_SCHEME="$(scheme "$PORTAL_PUBLIC_URL")"
  : > /etc/nginx/tls.inc
  : > /etc/nginx/http-redirect.inc
  mode="plain HTTP on :80 (TLS terminated in front)"
else
  export LISTEN="443 ssl" PUBLIC_SCHEME=https
  printf '%s\n' 'ssl_certificate     /pki/proxy/proxy-fullchain.crt;' \
    'ssl_certificate_key /pki/proxy/proxy.key;' 'ssl_protocols       TLSv1.2 TLSv1.3;' > /etc/nginx/tls.inc
  printf '%s\n' 'server {' '  listen 80;' '  location = /healthz { return 200 "ok\n"; }' \
    '  location / { return 301 https://$host$request_uri; }' '}' > /etc/nginx/http-redirect.inc
  mode="HTTPS on :443"
fi
envsubst '$PORTAL_HOST $PF_HOST $PF_UPSTREAM $LISTEN $PUBLIC_SCHEME' \
  < /proxy/nginx.conf.template > /etc/nginx/conf.d/default.conf
echo "[reverse-proxy] $mode: $PORTAL_HOST -> agentic-ai-service:8080, $PF_HOST -> $PF_UPSTREAM"
exec nginx -g 'daemon off;'
