#!/usr/bin/env bash
# Creates a self-signed certificate for localhost so the sample configuration can serve TLS.
# For development only: clients must be told to trust config/certs/localhost.crt.
set -euo pipefail

cd "$(dirname "$0")/.."
mkdir -p config/certs

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout config/certs/localhost.key -out config/certs/localhost.crt \
  -days 30 -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null

chmod 600 config/certs/localhost.key
echo "Wrote config/certs/localhost.crt and localhost.key (valid 30 days)."
