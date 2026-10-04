# OpenLDAP directory: system of record for people (entitlements) and agents (non-person entities).
FROM alpine:3.20
RUN apk add --no-cache openldap openldap-back-mdb openldap-clients
COPY icam.schema /etc/openldap/schema/icam.schema
COPY slapd.conf /etc/openldap/slapd.conf.tmpl
COPY seed.ldif /etc/openldap/seed.ldif
COPY entrypoint.sh /entrypoint.sh
# Strip CRs in case the repo was checked out with Windows line endings.
RUN sed -i 's/\r$//' /entrypoint.sh /etc/openldap/*.tmpl /etc/openldap/seed.ldif /etc/openldap/schema/icam.schema \
 && chmod +x /entrypoint.sh
EXPOSE 389
ENTRYPOINT ["/entrypoint.sh"]
