#!/usr/bin/env python3
"""
Approach A – mTLS Streaming Sender
Connects with mutual TLS and streams the file in fixed 1 MB chunks.
Sends a SHA-256 of the plaintext after the last chunk so the receiver
can verify end-to-end integrity.
"""

import hashlib
import os
import socket
import ssl
import struct
import sys
import time

HOST = os.environ.get("RECEIVER_HOST", "127.0.0.1")
PORT = int(os.environ.get("RECEIVER_PORT", "9443"))
CHUNK_SIZE = 1 * 1024 * 1024  # 1 MB

CERTS_DIR = os.path.join(os.path.dirname(__file__), "certs")


def main() -> None:
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <file_path>")
        sys.exit(1)

    file_path = sys.argv[1]
    file_size = os.path.getsize(file_path)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(
        os.path.join(CERTS_DIR, "client.crt"),
        os.path.join(CERTS_DIR, "client.key"),
    )
    ctx.load_verify_locations(os.path.join(CERTS_DIR, "ca.crt"))
    ctx.check_hostname = False  # self-signed CA; hostname check replaced by CA check

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw:
        with ctx.wrap_socket(raw) as tls:
            tls.connect((HOST, PORT))
            print(f"[+] Connected  cipher={tls.cipher()}")

            sha256 = hashlib.sha256()
            sent = 0
            t_start = time.monotonic()

            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    sha256.update(chunk)
                    tls.sendall(struct.pack(">I", len(chunk)))
                    tls.sendall(chunk)
                    sent += len(chunk)
                    print(
                        f"\r[+] Sent {sent // (1 << 20):,} / {file_size // (1 << 20):,} MiB",
                        end="",
                        flush=True,
                    )

            tls.sendall(struct.pack(">I", 0))           # end-of-stream marker
            digest = sha256.digest()
            tls.sendall(struct.pack(">I", len(digest)))
            tls.sendall(digest)
            # Wait for receiver's ACK before closing – prevents SSL close_notify race
            ack = tls.recv(1)
            elapsed = time.monotonic() - t_start
            status = "OK" if ack == b"\x00" else "INTEGRITY FAIL"
            mbps = (file_size / (1 << 20)) / elapsed if elapsed > 0 else 0
            print(f"\n[+] Done  SHA-256={sha256.hexdigest()}  receiver={status}")
            print(f"[+] Throughput: {mbps:.1f} MiB/s  elapsed={elapsed:.1f}s")


if __name__ == "__main__":
    main()
