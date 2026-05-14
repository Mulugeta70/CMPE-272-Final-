#!/usr/bin/env python3
"""
Approach B – Application-Layer Encrypted Envelope Receiver

Protocol:
  1. Mutual auth via Ed25519 signatures over ephemeral X25519 public keys.
  2. X25519 ECDH → HKDF-SHA256 → 32-byte session key (forward secrecy).
  3. Each chunk encrypted with ChaCha20-Poly1305; nonce = 4-byte counter || 8 zero bytes.
  4. End-of-stream = empty framed message; final SHA-256 sent encrypted.
  5. Receiver writes to a .tmp file; renames only after hash passes.
"""

import hashlib
import os
import socket
import struct
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, load_pem_private_key, load_pem_public_key,
)

HOST = os.environ.get("BIND_HOST", "127.0.0.1")
PORT = int(os.environ.get("BIND_PORT", "9444"))
CHUNK_SIZE = 1 * 1024 * 1024  # 1 MB
KEYS_DIR = os.path.join(os.path.dirname(__file__), "keys")

# Handshake layout: sign_pub(32) | signature(64) | eph_pub(32) = 128 bytes
HS_LEN = 128


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
    # 12-byte nonce: 4-byte big-endian counter padded with 8 zero bytes
    return struct.pack(">I", counter) + b"\x00" * 8


def main() -> None:
    output_path = sys.argv[1] if len(sys.argv) > 1 else "received_b.bin"
    tmp_path = output_path + ".tmp"

    # Load long-lived keys
    with open(os.path.join(KEYS_DIR, "receiver_signing.pem"), "rb") as f:
        signing_key: Ed25519PrivateKey = load_pem_private_key(f.read(), password=None)
    with open(os.path.join(KEYS_DIR, "sender_signing_pub.pem"), "rb") as f:
        sender_verify_key: Ed25519PublicKey = load_pem_public_key(f.read())

    signing_pub_bytes = signing_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    expected_sender_pub = sender_verify_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, PORT))
        srv.listen(1)
        print(f"[*] Listening on {HOST}:{PORT}")

        conn, addr = srv.accept()
        with conn:
            print(f"[+] Connection from {addr}")

            # ── Receive and verify sender's handshake ──────────────────────
            hs = recv_framed(conn)
            if len(hs) != HS_LEN:
                print("[!] Malformed handshake – dropping connection")
                sys.exit(1)

            sender_sign_pub = hs[:32]
            sender_sig       = hs[32:96]
            sender_eph_pub   = hs[96:128]

            if sender_sign_pub != expected_sender_pub:
                print("[!] AUTHENTICITY FAILURE – sender identity unknown")
                sys.exit(1)
            try:
                sender_verify_key.verify(sender_sig, sender_eph_pub)
            except InvalidSignature:
                print("[!] AUTHENTICITY FAILURE – bad sender signature")
                sys.exit(1)
            print("[+] Sender authenticated")

            # ── Send receiver's handshake ──────────────────────────────────
            eph_priv = X25519PrivateKey.generate()
            eph_pub_bytes = eph_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            sig = signing_key.sign(eph_pub_bytes)
            send_framed(conn, signing_pub_bytes + sig + eph_pub_bytes)

            # ── ECDH + HKDF key derivation ─────────────────────────────────
            peer_eph = X25519PublicKey.from_public_bytes(sender_eph_pub)
            shared = eph_priv.exchange(peer_eph)
            session_key = HKDF(
                algorithm=SHA256(), length=32, salt=None, info=b"secure-transfer-v1"
            ).derive(shared)
            chacha = ChaCha20Poly1305(session_key)
            print("[+] Session key derived (X25519 forward-secret ECDH)")

            # ── Receive and decrypt file chunks ───────────────────────────
            sha256 = hashlib.sha256()
            total = 0
            counter = 0

            try:
                with open(tmp_path, "wb") as out:
                    while True:
                        frame = recv_framed(conn)
                        if not frame:  # end-of-stream marker
                            break
                        plaintext = chacha.decrypt(make_nonce(counter), frame, None)
                        out.write(plaintext)
                        sha256.update(plaintext)
                        total += len(plaintext)
                        counter += 1
                        print(f"\r[+] Received {total // (1 << 20):,} MiB", end="", flush=True)

                # Receive and verify the encrypted SHA-256 hash
                enc_hash = recv_framed(conn)
                sender_hash = chacha.decrypt(make_nonce(counter), enc_hash, None)
                our_hash = sha256.digest()

                if sender_hash != our_hash:
                    os.unlink(tmp_path)
                    print("\n[!] INTEGRITY FAILURE – hash mismatch; partial file deleted.")
                    sys.exit(1)

                os.rename(tmp_path, output_path)
                print(f"\n[+] Transfer OK  SHA-256={our_hash.hex()}")
                print(f"[+] File saved: {output_path}")

            except Exception:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
                raise


if __name__ == "__main__":
    main()
