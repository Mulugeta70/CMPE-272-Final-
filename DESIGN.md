# Design Document — Secure 4 GB File Transfer

---

## Approach A — Mutual TLS (mTLS) Streaming

### Architecture Diagram

```
Sender (TLS Client)                    Receiver (TLS Server)
─────────────────────────────────────────────────────────────
  load client.crt / client.key           load server.crt / server.key
  load ca.crt                            load ca.crt
         │                                      │
         │  TCP SYN / SYN-ACK / ACK             │
         │─────────────────────────────────────>│
         │  TLS 1.3 ClientHello                 │
         │─────────────────────────────────────>│
         │  TLS 1.3 ServerHello + cert          │
         │<─────────────────────────────────────│
         │  Client cert + Finished              │
         │─────────────────────────────────────>│
         │  Server verifies client cert         │
         │                                      │
         │  [4-byte len][1 MB chunk] × N        │
         │─────────────────────────────────────>│  write to .tmp
         │  [4-byte 0x00000000]  (end marker)   │
         │─────────────────────────────────────>│
         │  [4-byte len][SHA-256 of plaintext]  │
         │─────────────────────────────────────>│  verify hash
         │  [1-byte ACK]                        │
         │<─────────────────────────────────────│  rename .tmp → output
```

### Key Exchange & Key Management

- A self-signed CA (`certs/ca.crt`) signs both the server cert and the client cert.
- TLS 1.3 performs ECDHE internally on every handshake, so session keys are
  forward-secret even if the long-lived private keys are later compromised.
- The CA private key (`certs/ca.key`) does not travel over the network;
  only the certificates are exchanged during the handshake.

### Chunking & Framing

```
[ 4-byte big-endian chunk length ][ chunk bytes (≤ 1 MB) ]
...repeat...
[ 4-byte 0x00000000 ]                     ← end-of-stream marker
[ 4-byte hash length (32) ][ 32-byte SHA-256 of full plaintext ]
[ 1-byte ACK from receiver ]
```

### Algorithms & Parameters

| Layer          | Algorithm            | Parameters                    |
|----------------|----------------------|-------------------------------|
| Transport      | TLS 1.3              | minimum_version = TLSv1.3     |
| AEAD (per rec) | AES-256-GCM          | provided by TLS automatically |
| Authentication | X.509 certificates   | RSA-4096, signed by shared CA |
| Hash           | SHA-256              | over full plaintext           |
| Chunk size     | 1 MB                 | fixed                         |

### Threat Model

| Threat | CIAA | Mechanism |
|--------|------|-----------|
| Passive eavesdropper | C | TLS 1.3 encrypts every byte; AES-256-GCM |
| Active MITM modifies bytes | I | AES-GCM AEAD tag fails; + final SHA-256 check |
| Attacker spoofs sender | A | Client must present CA-signed cert; TLS rejects unknown cert |
| Attacker spoofs receiver | A | Server must present CA-signed cert; TLS rejects unknown cert |
| Replay of old session | I/A | TLS 1.3 uses fresh ECDHE per session; no session resumption enabled |
| Drop at 80% | Av | Receiver writes to `.tmp`; only renames after hash passes; partial file is deleted |
| Untrusted broker | C/I | N/A – direct TCP; no broker in this approach |

---

## Approach B — Application-Layer Encrypted Envelope

### Architecture Diagram

```
Sender                                 Receiver
─────────────────────────────────────────────────────────────
load sender_signing.pem                load receiver_signing.pem
load receiver_signing_pub.pem          load sender_signing_pub.pem
generate ephemeral X25519 key pair     generate ephemeral X25519 key pair
         │                                      │
         │  TCP SYN / SYN-ACK / ACK             │
         │─────────────────────────────────────>│
         │  HANDSHAKE FRAME (128 bytes):        │
         │  sender_ed25519_pub (32)             │
         │  sign(sender_ed25519_priv,           │
         │       sender_eph_x25519_pub) (64)    │
         │  sender_eph_x25519_pub (32)          │
         │─────────────────────────────────────>│  verify sig
         │  HANDSHAKE FRAME (128 bytes):        │
         │  receiver_ed25519_pub (32)           │
         │  sign(receiver_ed25519_priv,         │
         │       receiver_eph_x25519_pub) (64)  │
         │  receiver_eph_x25519_pub (32)        │
         │<─────────────────────────────────────│
         verify sig                             verify sig
         │                                      │
         ECDH(sender_eph_priv,                  ECDH(receiver_eph_priv,
              receiver_eph_pub)                      sender_eph_pub)
         ──────────── same shared secret ────────────────────
         session_key = HKDF(shared, info="secure-transfer-v1")
         │                                      │
         │  [4-byte len][ChaCha20-Poly1305      │
         │   ciphertext of 1 MB chunk] × N      │
         │─────────────────────────────────────>│  decrypt, write .tmp
         │  [4-byte 0]  (end marker)            │
         │─────────────────────────────────────>│
         │  [4-byte len][encrypted SHA-256]     │
         │─────────────────────────────────────>│  verify hash
         │                                      │  rename .tmp → output
```

### Key Exchange & Key Management

- Each side has a long-lived **Ed25519** signing key pair (pre-distributed,
  analogous to a pre-shared public key).
- Each session generates a fresh **X25519** ephemeral key pair; the DH result
  is fed through **HKDF-SHA256** to produce a 32-byte session key.
- Because the session key derives from ephemeral keys, compromise of the
  long-lived Ed25519 keys does NOT expose past session keys (forward secrecy).

### Chunking & Framing

```
[ 4-byte len ][ ChaCha20-Poly1305 ciphertext of chunk_i ]
nonce_i = big-endian uint32(i) || 0x00 * 8   (12 bytes total)
...repeat for each 1 MB chunk...
[ 4-byte 0x00000000 ]                ← end-of-stream marker
[ 4-byte len ][ ChaCha20-Poly1305 ciphertext of SHA-256(plaintext) ]
nonce uses counter = num_chunks
```

### Algorithms & Parameters

| Layer              | Algorithm              | Parameters                     |
|--------------------|------------------------|--------------------------------|
| Identity / auth    | Ed25519                | 32-byte public key, 64-byte sig|
| Key exchange       | X25519 ECDH            | ephemeral per session          |
| Key derivation     | HKDF-SHA256            | 32-byte output, info tag       |
| AEAD (per chunk)   | ChaCha20-Poly1305      | 32-byte key, 12-byte nonce     |
| Nonce              | counter-based          | chunk index, never reused      |
| Hash               | SHA-256                | over full plaintext            |
| Chunk size         | 1 MB                   | fixed                          |

### Threat Model

| Threat | CIAA | Mechanism |
|--------|------|-----------|
| Passive eavesdropper | C | ChaCha20-Poly1305 encrypts every chunk; session key never on wire |
| Active MITM modifies bytes | I | Poly1305 AEAD tag fails per chunk; + final SHA-256 check |
| Attacker spoofs sender | A | Sender signs its ephemeral X25519 key with Ed25519; receiver verifies against pre-loaded public key |
| Attacker spoofs receiver | A | Receiver signs its ephemeral key; sender verifies against pre-loaded public key |
| Replay of old session | I/A | Fresh ephemeral X25519 keys per session produce a different session key each time |
| Drop at 80% | Av | Receiver writes to `.tmp`; only renames after SHA-256 passes; partial file deleted on failure |
| Untrusted broker | C/I | N/A – direct TCP; no broker. If broker were added, encrypt-then-send means broker never sees plaintext |

---

## Forward Secrecy — Why It Matters Here

Both approaches provide forward secrecy: compromise of a long-lived key after
the transfer is complete does not expose the file contents.

- **Approach A**: TLS 1.3 always performs a fresh ECDHE key exchange. Even if
  the server's RSA private key (`server.key`) is stolen later, past session
  keys cannot be reconstructed because they were derived from ephemeral keys
  that are deleted after the handshake.
- **Approach B**: Each session generates a fresh X25519 key pair. Even if
  the Ed25519 signing key is stolen, it was only used to authenticate the
  ephemeral key — not to encrypt data. The session key derived via HKDF from
  the ephemeral ECDH is gone once the connection closes.

**Why this matters for a 4 GB file transfer**: Large files are high-value
targets. An attacker may record the ciphertext now and wait to obtain the
long-lived keys later ("harvest now, decrypt later"). Forward secrecy makes
that strategy useless — the session key was ephemeral and no longer exists.

---

## Crypto Library Justification

| Library | Used in | Why chosen |
|---------|---------|------------|
| Python `ssl` stdlib | Approach A | Wraps OpenSSL/BoringSSL; FIPS-audited; zero extra dependencies |
| `cryptography` (PyCA) | Approach B | Actively maintained; audited; exposes X25519, Ed25519, ChaCha20-Poly1305, HKDF with correct defaults |

No hand-rolled cipher implementations are used anywhere. Both libraries are
on the professor's approved list.

---

## Why the Two Approaches Differ Architecturally

| Dimension            | Approach A (mTLS)            | Approach B (App-Layer Envelope)    |
|----------------------|------------------------------|------------------------------------|
| Security layer       | Transport (TLS 1.3)          | Application (hand-crafted protocol)|
| AEAD algorithm       | AES-256-GCM (via TLS)        | ChaCha20-Poly1305 (explicit)       |
| Authentication basis | X.509 certificates + CA      | Ed25519 signing keys (no CA)       |
| Key exchange         | TLS internal ECDHE           | Explicit X25519 ECDH + HKDF        |
| Nonce management     | Handled by TLS               | Explicit per-chunk counter         |
| Dependency           | OpenSSL / ssl stdlib         | `cryptography` library             |
| Forward secrecy      | TLS 1.3 (automatic)          | Explicit ephemeral X25519          |
