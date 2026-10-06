#!/bin/sh
# Renders nginx.conf.template from the public URLs, then runs nginx.
set -eu
host() { printf '%s' "$1" | sed -E 's#^[a-z]+://##; s#[/:].*$##'; }
export PORTAL_HOST="$(host "$PORTAL_PUBLIC_URL")" PF_HOST="$(host "$PF_PUBLIC_URL")"
envsubst '$PORTAL_HOST $PF_HOST $PF_UPSTREAM' < /proxy/nginx.conf.template > /etc/nginx/conf.d/default.conf
echo "[reverse-proxy] https://$PORTAL_HOST -> agentic-ai-service:8080, https://$PF_HOST -> $PF_UPSTREAM"
exec nginx -g 'daemon off;'
