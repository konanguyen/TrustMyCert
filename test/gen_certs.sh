#!/bin/bash
# Generate test-only certificates for the controlled TrustMyCert test server.
# NEVER use these for anything but local testing. NEVER commit real keys.
set -euo pipefail
cd "$(dirname "$0")/certs"
mkdir -p certs 2>/dev/null || true
cd certs

# Test CA.
openssl req -x509 -newkey rsa:2048 -keyout test-ca.key -out test-ca.crt \
  -days 2 -nodes -subj "/CN=TrustMyCert Test CA" 2>/dev/null

# Server cert signed by the test CA (CN=localhost).
openssl req -newkey rsa:2048 -keyout server.key -out server.csr -nodes \
  -subj "/CN=localhost" 2>/dev/null
printf "subjectAltName=DNS:localhost,IP:127.0.0.1" > server.ext
openssl x509 -req -in server.csr -CA test-ca.crt -CAkey test-ca.key \
  -CAcreateserial -out server.crt -days 2 -extfile server.ext 2>/dev/null

# SPKI pin of the server cert (DER SPKI -> sha256 -> base64), RFC 7469 style.
openssl x509 -in server.crt -pubkey -noout \
  | openssl pkey -pubin -outform DER 2>/dev/null \
  | openssl dgst -sha256 -binary | openssl enc -base64

echo "--- done. Test CA: test-ca.crt | server: server.crt/server.key (2-day validity)"
