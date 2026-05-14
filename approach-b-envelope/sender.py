#!/usr/bin/env python3
"""
Approach B – Application-Layer Encrypted Envelope Sender

Protocol:
  1. Send Ed25519 signing public key + signature over ephemeral X25519 public key.
  2. Receive and verify receiver's equivalent handshake.
  3. ECDH on ephemeral keys → HKDF-SHA256 → 32-byte session key.
  4. Stream file in 1 MB chunks encrypted with ChaCha20-Poly1305.
  5. Send empty frame (end-of-stream), then encrypted SHA-256 of full plaintext.
"""

import hashlib
import os
import socket
import struct
import sys
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, load_pem_private_key, load_pem_public_key,
)

HOST = os.environ.get("RECEIVER_HOST", "127.0.0.1")
PORT = int(os.environ.get("RECEIVER_PORT", "9444"))
CHUNK_SIZE = 1 * 1024 * 1024  # 1 MB
KEYS_DIR = os.path.join(os.path.dirname(__file__), "keys")

HS_LEN = 128  # sign_pub(32) | signature(64) | eph_pub(32)


def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        data = sock.recv(n - len(buf))
        if not data:
            raise ConnectionError("Connection closed unexpectedly")
        buf.extend(data)
    return bytes(buf)


def recv_framed(sock: socket.socket) -> bytes:
    n = struct.unpack(">I", recv_exact(sock, 4))[0]
    return recv_exact(sock, n) if n else b""


def send_framed(sock: socket.socket, data: bytes) -> None:
    sock.sendall(struct.pack(">I", len(data)) + data)


def make_nonce(counter: int) -> bytes:
    return struct.pack(">I", counter) + b"\x00" * 8


def main() -> None:
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <file_path>")
        sys.exit(1)

    file_path = sys.argv[1]
    file_size = os.path.getsize(file_path)

    # Load long-lived keys
    with open(os.path.join(KEYS_DIR, "sender_signing.pem"), "rb") as f:
        signing_key: Ed25519PrivateKey = load_pem_private_key(f.read(), password=None)
    with open(os.path.join(KEYS_DIR, "receiver_signing_pub.pem"), "rb") as f:
        receiver_verify_key: Ed25519PublicKey = load_pem_public_key(f.read())

    sign_pub_bytes = signing_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    expected_recv_pub = receiver_verify_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        print(f"[+] Connected to {HOST}:{PORT}")

        # ── Send sender's handshake ────────────────────────────────────────
        eph_priv = X25519PrivateKey.generate()
        eph_pub_bytes = eph_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        sig = signing_key.sign(eph_pub_bytes)
        send_framed(sock, sign_pub_bytes + sig + eph_pub_bytes)

        # ── Receive and verify receiver's handshake ────────────────────────
        hs = recv_framed(sock)
        if len(hs) != HS_LEN:
            print("[!] Malformed handshake")
            sys.exit(1)

        recv_sign_pub = hs[:32]
        recv_sig       = hs[32:96]
        recv_eph_pub   = hs[96:128]

        if recv_sign_pub != expected_recv_pub:
            print("[!] AUTHENTICITY FAILURE – receiver identity unknown")
            sys.exit(1)
        try:
            receiver_verify_key.verify(recv_sig, recv_eph_pub)
        except InvalidSignature:
            print("[!] AUTHENTICITY FAILURE – bad receiver signature")
            sys.exit(1)
        print("[+] Receiver authenticated")

        # ── ECDH + HKDF key derivation ─────────────────────────────────────
        peer_eph = X25519PublicKey.from_public_bytes(recv_eph_pub)
        shared = eph_priv.exchange(peer_eph)
        session_key = HKDF(
            algorithm=SHA256(), length=32, salt=None, info=b"secure-transfer-v1"
        ).derive(shared)
        chacha = ChaCha20Poly1305(session_key)
        print("[+] Session key derived (X25519 forward-secret ECDH)")

        # ── Stream file ────────────────────────────────────────────────────
        sha256 = hashlib.sha256()
        sent = 0
        counter = 0
        t_start = time.monotonic()

        with open(file_path, "rb") as f:
            while True:
                plaintext = f.read(CHUNK_SIZE)
                if not plaintext:
                    break
                sha256.update(plaintext)
                ciphertext = chacha.encrypt(make_nonce(counter), plaintext, None)
                send_framed(sock, ciphertext)
                sent += len(plaintext)
                counter += 1
                print(
                    f"\r[+] Sent {sent // (1 << 20):,} / {file_size // (1 << 20):,} MiB",
                    end="",
                    flush=True,
                )

        send_framed(sock, b"")  # end-of-stream marker

        file_hash = sha256.digest()
        enc_hash = chacha.encrypt(make_nonce(counter), file_hash, None)
        send_framed(sock, enc_hash)
        elapsed = time.monotonic() - t_start
        mbps = (file_size / (1 << 20)) / elapsed if elapsed > 0 else 0
        print(f"\n[+] Done  SHA-256={sha256.hexdigest()}")
        print(f"[+] Throughput: {mbps:.1f} MiB/s  elapsed={elapsed:.1f}s")


if __name__ == "__main__":
    main()
