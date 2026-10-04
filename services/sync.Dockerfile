# directory-sync: the Python services image plus the spire-server CLI (to manage
# registration entries through the SPIRE Server's admin socket).
ARG SPIRE_VERSION=1.13.3
FROM ghcr.io/spiffe/spire-server:${SPIRE_VERSION} AS spire

FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY --from=spire /opt/spire/bin/spire-server /usr/local/bin/spire-server
COPY icam ./icam
