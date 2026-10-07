#!/bin/sh
# Installs the PingFederate license, then hands over to the image's own bootstrap.
# Sources, first match wins:
#   PF_LICENSE         the license file's content (multi-line; "\n"-escaped single line also accepted)
#   PF_LICENSE_BASE64  the same, base64-encoded (for platforms without multi-line variables)
#   /opt/icam/license  bind mount of PF_LICENSE_FILE: the license file, or a directory holding
#                      pingfederate.lic (default: ./pingfederate/license)
set -eu
dest=/opt/in/instance/server/default/conf/pingfederate.lic
mkdir -p "$(dirname "$dest")"
src=/opt/icam/license
if [ -n "${PF_LICENSE:-}" ]; then
  case "$PF_LICENSE" in
    *'
'*) printf '%s' "$PF_LICENSE" ;;
    *) printf '%b' "$PF_LICENSE" ;;       # one line with literal \n sequences
  esac | tr -d '\r' > "$dest"
  from="PF_LICENSE variable"
elif [ -n "${PF_LICENSE_BASE64:-}" ]; then
  printf '%s' "$PF_LICENSE_BASE64" | tr -d ' \r\n' | base64 -d | tr -d '\r' > "$dest"
  from="PF_LICENSE_BASE64 variable"
elif [ -f "$src" ]; then
  tr -d '\r' < "$src" > "$dest"; from="PF_LICENSE_FILE"
elif [ -f "$src/pingfederate.lic" ]; then
  tr -d '\r' < "$src/pingfederate.lic" > "$dest"; from="pingfederate/license/pingfederate.lic"
else
  echo "[license] no PingFederate license: set PF_LICENSE (content), PF_LICENSE_BASE64, or PF_LICENSE_FILE," >&2
  echo "[license] or copy it to pingfederate/license/pingfederate.lic" >&2
  exit 1
fi
if ! grep -q '^ID=' "$dest"; then
  echo "[license] the license from $from has no ID= line - not a PingFederate license file?" >&2
  exit 1
fi
echo "[license] installed from $from (ID $(sed -n 's/^ID=//p' "$dest" | head -1))"
unset PF_LICENSE PF_LICENSE_BASE64     # keep the content out of the server's environment
cd /opt
exec ./bootstrap.sh "$@"
