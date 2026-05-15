# Secure 4 GB File Transfer — CMPE 272 Final Q10

Two architecturally distinct approaches for securely transferring a large file
over an untrusted network, both satisfying CIAA (Confidentiality, Integrity,
Authenticity, Availability).

---

## Prerequisites

```bash
# Python 3.9+ and OpenSSL must be installed
python3 --version
openssl version
pip install cryptography   # or: apt install python3-cryptography
```

---

## Generate the 4 GB test file

```bash
# Linux / macOS
dd if=/dev/urandom of=test_4gb.bin bs=1M count=4096

# Cross-platform Python
python3 -c "open('test_4gb.bin','wb').write(b'\0'*4*1024*1024*1024)"
```

---

## Approach A — Mutual TLS (mTLS) Streaming

**Architecture:** Receiver runs a TLS 1.3 server; sender is a TLS client.
Both sides present X.509 certificates signed by a shared CA — that is mutual
authentication. TLS handles AEAD (AES-256-GCM) per record automatically.

> **Note:** Certificates are pre-generated and included in the repo under
> `approach-a-mtls/certs/`. Run `bash gen_certs.sh` only if you want to
> regenerate them.

### 1. Start the receiver (terminal 1)

```bash
cd approach-a-mtls
python3 receiver.py ../received_a.bin
# Listens on 127.0.0.1:9443
```

### 2. Run the sender (terminal 2)

```bash
cd approach-a-mtls
python3 sender.py ../test_4gb.bin
```

### 3. Verify hashes match

```bash
# Run from the project root (secure-transfer/)
sha256sum test_4gb.bin received_a.bin
```

Both lines must show the same SHA-256 hex digest.

---

## Approach B — Application-Layer Encrypted Envelope

**Architecture:** Plain TCP socket; all security is implemented at the
application layer using X25519 ECDH + Ed25519 mutual auth + ChaCha20-Poly1305
AEAD per chunk. Gives explicit forward secrecy and does not depend on TLS.

> **Note:** Ed25519 signing key pairs are pre-generated and included in the
> repo under `approach-b-envelope/keys/`. Run `python3 gen_keys.py` only if
> you want to regenerate them.

### 1. Start the receiver (terminal 1)

```bash
cd approach-b-envelope
python3 receiver.py ../received_b.bin
# Listens on 127.0.0.1:9444
```

### 2. Run the sender (terminal 2)

```bash
cd approach-b-envelope
python3 sender.py ../test_4gb.bin
```

### 3. Verify hashes match

```bash
# Run from the project root (secure-transfer/)
sha256sum test_4gb.bin received_b.bin
```

---

## Threat Model Tests

Three automated tests verify the security properties of both approaches:

```bash
# Run from the project root (secure-transfer/)

# Test 1: Tamper a byte mid-transfer → receiver detects and rejects
python3 tests/test1_tamper_byte.py

# Test 2: Kill connection at 80% → no partial file left on disk
python3 tests/test2_kill_connection.py

# Test 3: Wrong key / no certificate → connection rejected immediately
python3 tests/test3_wrong_key.py
```

All three tests should print `[+] PASS` for both approaches.

---

## Run both approaches at once (automated test)

```bash
# Run from the project root (secure-transfer/)
python3 run_test.py
```

Runs Approach A then Approach B sequentially, transfers the 4 GB file through
each, and verifies SHA-256 matches on both sides.

---

## Environment variables

| Variable        | Default     | Effect                         |
|-----------------|-------------|--------------------------------|
| BIND_HOST       | 127.0.0.1   | Address the receiver binds to  |
| BIND_PORT       | 9443 / 9444 | Port the receiver listens on   |
| RECEIVER_HOST   | 127.0.0.1   | Address the sender connects to |
| RECEIVER_PORT   | 9443 / 9444 | Port the sender connects to    |

---

## Chunk size

Both approaches use **1 MB chunks** (`CHUNK_SIZE = 1 * 1024 * 1024`).
This keeps memory usage constant regardless of file size and matches
typical TLS record / socket buffer sizing without excessive overhead per chunk.

---

## Crypto library justification

| Library               | Approach | Justification                                                                 |
|-----------------------|----------|-------------------------------------------------------------------------------|
| Python `ssl` stdlib   | A        | Ships with CPython; wraps OpenSSL/BoringSSL; no extra install needed          |
| `cryptography` (PyCA) | B        | Actively maintained, audited; provides X25519, Ed25519, ChaCha20-Poly1305, HKDF; on professor's approved list |

Neither library is exotic. No custom cipher code exists anywhere in this project.

---

## Forward secrecy

Both approaches provide forward secrecy. A recorded ciphertext cannot be
decrypted later even if the long-lived keys are later stolen, because each
session derives its encryption key from ephemeral keys that are discarded
after the handshake. See DESIGN.md for the full explanation.
