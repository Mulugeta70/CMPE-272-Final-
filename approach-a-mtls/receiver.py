#!/usr/bin/env python3
"""
Approach A – mTLS Streaming Receiver
Listens for an mTLS connection, receives the file in chunks, and verifies
the sender's SHA-256 hash before committing the file to disk.
"""

import hashlib
import os
import socket
import ssl
import struct
import sys

HOST = os.environ.get("BIND_HOST", "127.0.0.1")
PORT = int(os.environ.get("BIND_PORT", "9443"))
CHUNK_SIZE = 1 * 1024 * 1024  # 1 MB

CERTS_DIR = os.path.join(os.path.dirname(__file__), "certs")


def recv_exact(conn: ssl.SSLSocket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        data = conn.recv(n - len(buf))
        if not data:
            raise ConnectionError("Connection closed before all bytes arrived")
        buf.extend(data)
    return bytes(buf)


def main() -> None:
    output_path = sys.argv[1] if len(sys.argv) > 1 else "received_a.bin"
    tmp_path = output_path + ".tmp"

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(
        os.path.join(CERTS_DIR, "server.crt"),
        os.path.join(CERTS_DIR, "server.key"),
    )
    ctx.load_verify_locations(os.path.join(CERTS_DIR, "ca.crt"))
    ctx.verify_mode = ssl.CERT_REQUIRED  # mutual TLS – reject uncertified clients

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw:
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        raw.bind((HOST, PORT))
        raw.listen(1)
        print(f"[*] Listening on {HOST}:{PORT}")

        conn, addr = raw.accept()
        with ctx.wrap_socket(conn, server_side=True) as tls:
            print(f"[+] Connection from {addr}  cipher={tls.cipher()}")
            sha256 = hashlib.sha256()
            total = 0

            try:
                with open(tmp_path, "wb") as out:
                    while True:
                        header = recv_exact(tls, 4)
                        chunk_len = struct.unpack(">I", header)[0]
                        if chunk_len == 0:  # end-of-stream marker
                            break
                        data = recv_exact(tls, chunk_len)
                        out.write(data)
                        sha256.update(data)
                        total += chunk_len
                        print(f"\r[+] Received {total // (1 << 20):,} MiB", end="", flush=True)

                # Receive the framed SHA-256 hash and compare
                hash_len_bytes = recv_exact(tls, 4)
                hash_len = struct.unpack(">I", hash_len_bytes)[0]
                sender_hash = recv_exact(tls, hash_len)
                our_hash = sha256.digest()

                if sender_hash != our_hash:
                    tls.sendall(b"\x01")  # NAK
                    os.unlink(tmp_path)
                    print("\n[!] INTEGRITY FAILURE – hash mismatch; partial file deleted.")
                    sys.exit(1)

                tls.sendall(b"\x00")  # ACK – tells sender it may close cleanly
                os.rename(tmp_path, output_path)
                print(f"\n[+] Transfer OK  SHA-256={our_hash.hex()}")
                print(f"[+] File saved: {output_path}")

            except Exception:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
                raise


if __name__ == "__main__":
    main()
