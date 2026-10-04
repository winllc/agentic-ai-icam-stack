#!/bin/sh
# Seeds the directory on first start (passwords hashed with slappasswd), then runs slapd.
set -eu
hash() { slappasswd -s "$1"; }
mkdir -p /run/openldap /var/lib/openldap/data
sed "s|@ROOTPW@|$(hash "${LDAP_ADMIN_PASSWORD:-admin}")|" /etc/openldap/slapd.conf.tmpl > /etc/openldap/slapd.conf
if [ ! -f /var/lib/openldap/data/data.mdb ]; then
  echo "[ldap] seeding dc=demo,dc=local"
  sed -e "s|@SYNC_PW@|$(hash "${LDAP_SYNC_PASSWORD:-sync-secret}")|" \
      -e "s|@IDP_PW@|$(hash "${LDAP_IDP_PASSWORD:-idp-secret}")|" \
      -e "s|@ALICE_PW@|$(hash alice)|" -e "s|@BOB_PW@|$(hash bob)|" \
      /etc/openldap/seed.ldif | slapadd -f /etc/openldap/slapd.conf
fi
exec slapd -f /etc/openldap/slapd.conf -h "ldap:///" -d stats
