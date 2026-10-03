# Small toolbox image: openssl for the demo PKI + the spire-server CLI for
# registering entries against the server's admin socket.
ARG SPIRE_VERSION=1.13.3
FROM ghcr.io/spiffe/spire-server:${SPIRE_VERSION} AS spire

FROM alpine:3.20
RUN apk add --no-cache openssl bash
COPY --from=spire /opt/spire/bin/spire-server /usr/local/bin/spire-server
COPY pki-init.sh register.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/*.sh
