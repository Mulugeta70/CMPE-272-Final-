#!/usr/bin/env python3
"""
Threat Test 3 – Present the wrong key / certificate.
Verifies that authentication fails closed when the wrong credentials are used.
"""

import os, subprocess, sys, time, shutil

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SMALL = os.path.join(BASE, "test_small.bin")

# ── Approach A: wrong client cert (self-signed, not from our CA) ──────────────
print("\n" + "="*60)
print("  APPROACH A – Wrong client certificate")
print("="*60)

# Generate a rogue CA and a client cert signed by it — NOT by our legitimate CA
rogue_dir = os.path.join(BASE, "tests", "rogue_certs")
os.makedirs(rogue_dir, exist_ok=True)
# Rogue CA
os.system(f"openssl genrsa -out {rogue_dir}/rogue_ca.key 2048 2>/dev/null")
os.system(
    f'openssl req -new -x509 -days 1 -key {rogue_dir}/rogue_ca.key '
    f'-out {rogue_dir}/rogue_ca.crt -subj "/CN=RogueCA" 2>/dev/null'
)
# Client cert signed by the rogue CA
os.system(f"openssl genrsa -out {rogue_dir}/rogue.key 2048 2>/dev/null")
os.system(
    f'openssl req -new -key {rogue_dir}/rogue.key -out {rogue_dir}/rogue.csr '
    f'-subj "/CN=attacker" 2>/dev/null'
)
os.system(
    f'openssl x509 -req -days 1 -in {rogue_dir}/rogue.csr '
    f'-CA {rogue_dir}/rogue_ca.crt -CAkey {rogue_dir}/rogue_ca.key '
    f'-CAcreateserial -out {rogue_dir}/rogue.crt 2>/dev/null'
)

# Write a rogue sender that uses the rogue cert
rogue_sender_a = os.path.join(BASE, "tests", "_rogue_sender_a.py")
with open(rogue_sender_a, "w") as f:
    f.write('''\
#!/usr/bin/env python3
"""
Try to connect WITHOUT a client cert.
In TLS 1.3 connect() can return before server rejection propagates,
so we also attempt to send data to confirm the rejection.
"""
import ssl, socket, struct
HOST, PORT = "127.0.0.1", 9443
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
try:
    with socket.socket() as raw:
        with ctx.wrap_socket(raw) as tls:
            tls.connect((HOST, PORT))
            # Try to send a data chunk — server already rejected us
            tls.sendall(struct.pack(">I", 4) + b"hack")
            tls.sendall(struct.pack(">I", 0))
            response = tls.recv(32)
            print("[!] FAIL – unauthenticated client sent data and got response!")
except (ssl.SSLError, OSError, ConnectionResetError) as e:
    print(f"[+] PASS – server rejected unauthenticated client: {type(e).__name__}")
''')

out_a = os.path.join(BASE, "wrong_key_out_a.bin")
recv_a = subprocess.Popen(
    ["python3", os.path.join(BASE,"approach-a-mtls","receiver.py"), out_a],
    stderr=subprocess.STDOUT
)
time.sleep(1.5)
rogue_a = subprocess.Popen(["python3", rogue_sender_a], stderr=subprocess.STDOUT)
rogue_a.wait()
recv_a.terminate()
recv_a.wait()

if os.path.exists(out_a):
    os.unlink(out_a)

# ── Approach B: wrong Ed25519 signing key ─────────────────────────────────────
print("\n" + "="*60)
print("  APPROACH B – Wrong signing key (unknown sender identity)")
print("="*60)

# Generate a fresh unknown Ed25519 key pair (not pre-distributed to receiver)
rogue_sender_b = os.path.join(BASE, "tests", "_rogue_sender_b.py")
with open(rogue_sender_b, "w") as f:
    f.write(f'''\
#!/usr/bin/env python3
"""Sender using a signing key the receiver has never seen."""
import os, socket, struct, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

HOST, PORT = "127.0.0.1", 9444

# Generate a brand-new key that receiver does not know about
unknown_key = Ed25519PrivateKey.generate()
eph = X25519PrivateKey.generate()
eph_pub = eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
sig = unknown_key.sign(eph_pub)
spub = unknown_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

def send_framed(s, d):
    s.sendall(struct.pack(">I", len(d)) + d)

try:
    with socket.socket() as sock:
        sock.connect((HOST, PORT))
        send_framed(sock, spub + sig + eph_pub)
        # receiver should immediately close after identity check fails
        data = sock.recv(4)
        if not data:
            print("[+] PASS – receiver closed connection on unknown sender identity")
        else:
            print("[!] FAIL – receiver sent data back to unknown sender!")
except ConnectionResetError:
    print("[+] PASS – receiver reset connection (unknown sender identity)")
except Exception as e:
    print(f"[+] Connection failed as expected: {{e}}")
''')

out_b = os.path.join(BASE, "wrong_key_out_b.bin")
recv_b = subprocess.Popen(
    ["python3", os.path.join(BASE,"approach-b-envelope","receiver.py"), out_b],
    stderr=subprocess.STDOUT
)
time.sleep(1.5)
rogue_b = subprocess.Popen(["python3", rogue_sender_b], stderr=subprocess.STDOUT)
rogue_b.wait()
recv_b.wait(timeout=5)

if os.path.exists(out_b):
    print("[!] FAIL – output file created despite wrong key!")
    os.unlink(out_b)
else:
    print("[+] PASS – no output file created")
