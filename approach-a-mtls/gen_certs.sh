#!/usr/bin/env bash
set -euo pipefail
mkdir -p certs

# Self-signed CA
openssl genrsa -out certs/ca.key 4096 2>/dev/null
openssl req -new -x509 -days 3650 -key certs/ca.key -out certs/ca.crt \
    -subj "/CN=TransferCA" 2>/dev/null

# Server (receiver) cert signed by CA
openssl genrsa -out certs/server.key 4096 2>/dev/null
openssl req -new -key certs/server.key -out certs/server.csr \
    -subj "/CN=receiver" 2>/dev/null
openssl x509 -req -days 3650 -in certs/server.csr \
    -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial \
    -out certs/server.crt 2>/dev/null

# Client (sender) cert signed by CA
openssl genrsa -out certs/client.key 4096 2>/dev/null
openssl req -new -key certs/client.key -out certs/client.csr \
    -subj "/CN=sender" 2>/dev/null
openssl x509 -req -days 3650 -in certs/client.csr \
    -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial \
    -out certs/client.crt 2>/dev/null

echo "[+] Certificates written to certs/"
