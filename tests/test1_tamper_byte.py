#!/usr/bin/env python3
"""
Threat Test 1 – Tamper a byte in the ciphertext mid-transfer.
Approach A: flip one byte in a copy of the source file → SHA-256 mismatch caught.
Approach B: flip one byte in the ciphertext of chunk 2 → AEAD tag rejection.
"""

import hashlib, os, shutil, socket, struct, subprocess, sys, time

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SMALL = os.path.join(BASE, "test_small.bin")

# Create a small 5 MB test file for speed
if not os.path.exists(SMALL):
    with open(SMALL, "wb") as f:
        f.write(os.urandom(5 * 1024 * 1024))
    print(f"[*] Created {SMALL}")

# Clean up any leftover output files from previous runs
for _f in ["tamper_out_a.bin", "tamper_out_b.bin"]:
    _p = os.path.join(BASE, _f)
    if os.path.exists(_p):
        os.unlink(_p)

# ── Approach A tamper: send tampered data but claim original file's hash ──────
print("\n" + "="*60)
print("  APPROACH A – Tamper Test (tampered data, original hash → mismatch)")
print("="*60)

tampered = SMALL + ".tampered"
shutil.copy(SMALL, tampered)
with open(tampered, "r+b") as f:
    f.seek(1024 * 1024 + 7)   # byte inside chunk 2
    b = f.read(1)
    f.seek(-1, 1)
    f.write(bytes([b[0] ^ 0xFF]))  # flip all bits
print("[*] Flipped one byte at offset 1,048,583 in tampered copy")

# Rogue sender: streams tampered file but sends hash of ORIGINAL file
# → receiver hash of tampered data ≠ hash of original → INTEGRITY FAILURE
rogue_sender_a = os.path.join(BASE, "tests", "_rogue_sender_a.py")
with open(rogue_sender_a, "w") as f:
    f.write('''\
#!/usr/bin/env python3
"""Rogue Approach A sender: sends tampered data but the original file hash."""
import hashlib, os, socket, ssl, struct, sys
CERTS_DIR = os.path.join(os.path.dirname(__file__), "..", "approach-a-mtls", "certs")
CHUNK_SIZE = 1 * 1024 * 1024
tampered_path, original_path = sys.argv[1], sys.argv[2]

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
ctx.load_cert_chain(os.path.join(CERTS_DIR,"client.crt"), os.path.join(CERTS_DIR,"client.key"))
ctx.load_verify_locations(os.path.join(CERTS_DIR,"ca.crt"))
ctx.check_hostname = False

# Compute hash of the ORIGINAL file
original_hash = hashlib.sha256(open(original_path,"rb").read()).digest()

with socket.socket() as raw:
    with ctx.wrap_socket(raw) as tls:
        tls.connect(("127.0.0.1", 9443))
        with open(tampered_path, "rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk: break
                tls.sendall(struct.pack(">I", len(chunk)) + chunk)
        tls.sendall(struct.pack(">I", 0))                     # end marker
        tls.sendall(struct.pack(">I", len(original_hash)) + original_hash)  # WRONG hash
        print("[*] Sent tampered data with original file hash — mismatch expected")
        tls.recv(1)  # wait for NAK/ACK
''')

out_a = os.path.join(BASE, "tamper_out_a.bin")
recv = subprocess.Popen(
    ["python3", os.path.join(BASE,"approach-a-mtls","receiver.py"), out_a],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
)
time.sleep(1.5)
send = subprocess.Popen(
    ["python3", rogue_sender_a, tampered, SMALL],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
)
send.wait(); recv.wait()

if os.path.exists(out_a):
    print("[!] FAIL – tampered file was accepted and saved!")
else:
    print("[+] PASS – receiver rejected tampered file (hash mismatch); no output file created")

os.unlink(tampered)

# ── Approach B tamper: flip one byte in ciphertext → AEAD tag failure ─────────
print("\n" + "="*60)
print("  APPROACH B – Tamper Test (flip byte in ciphertext chunk)")
print("="*60)

# Write a one-shot tampered sender that flips a byte in chunk 2's ciphertext
tampered_sender = os.path.join(BASE, "tests", "_tampered_sender_b.py")
with open(tampered_sender, "w") as f:
    f.write('''\
#!/usr/bin/env python3
"""Modified Approach B sender that flips one byte in chunk 2 ciphertext."""
import hashlib, os, socket, struct, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, load_pem_private_key, load_pem_public_key,
)

HOST, PORT = "127.0.0.1", 9444
CHUNK_SIZE = 1 * 1024 * 1024
KEYS_DIR = os.path.join(os.path.dirname(__file__), "..", "approach-b-envelope", "keys")

def recv_exact(s, n):
    b = bytearray()
    while len(b) < n:
        d = s.recv(n - len(b))
        if not d: raise ConnectionError()
        b.extend(d)
    return bytes(b)

def recv_framed(s):
    n = struct.unpack(">I", recv_exact(s, 4))[0]
    return recv_exact(s, n) if n else b""

def send_framed(s, data):
    s.sendall(struct.pack(">I", len(data)) + data)

def make_nonce(i):
    return struct.pack(">I", i) + b"\\x00" * 8

file_path = sys.argv[1]
with open(os.path.join(KEYS_DIR, "sender_signing.pem"), "rb") as f:
    sk = load_pem_private_key(f.read(), password=None)
with open(os.path.join(KEYS_DIR, "receiver_signing_pub.pem"), "rb") as f:
    rvk = load_pem_public_key(f.read())

eph = X25519PrivateKey.generate()
eph_pub = eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
sig = sk.sign(eph_pub)
spub = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

with socket.socket() as sock:
    sock.connect((HOST, PORT))
    send_framed(sock, spub + sig + eph_pub)
    hs = recv_framed(sock)
    rvk.verify(hs[32:96], hs[96:128])
    peer = X25519PublicKey.from_public_bytes(hs[96:128])
    shared = eph.exchange(peer)
    key = HKDF(SHA256(), 32, None, b"secure-transfer-v1").derive(shared)
    chacha = ChaCha20Poly1305(key)

    sha256 = hashlib.sha256()
    counter = 0
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk: break
            sha256.update(chunk)
            ct = bytearray(chacha.encrypt(make_nonce(counter), chunk, None))
            if counter == 1:          # flip one byte in chunk 2 ciphertext
                ct[42] ^= 0xFF
                print("[*] Flipped byte 42 of chunk 2 ciphertext")
            send_framed(sock, bytes(ct))
            counter += 1
    send_framed(sock, b"")
    h = sha256.digest()
    send_framed(sock, chacha.encrypt(make_nonce(counter), h, None))
    print(f"[*] Tampered transfer complete")
''')

out_b = os.path.join(BASE, "tamper_out_b.bin")
recv2 = subprocess.Popen(
    ["python3", os.path.join(BASE,"approach-b-envelope","receiver.py"), out_b],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
)
time.sleep(1.5)
send2 = subprocess.Popen(
    ["python3", tampered_sender, SMALL],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
)
send2.wait(); recv2.wait()

if os.path.exists(out_b):
    print("[!] FAIL – tampered file was accepted!")
else:
    print("[+] PASS – receiver rejected tampered ciphertext (AEAD tag failure); no output file")
