#!/usr/bin/env python3
"""Run both approaches end-to-end and verify hashes match."""
import hashlib, subprocess, sys, time, os, signal

BASE = os.path.dirname(os.path.abspath(__file__))
TEST = os.path.join(BASE, "test_4gb.bin")

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def run_approach(label, recv_cmd, send_cmd, out_path):
    print(f"\n{'='*60}")
    print(f"  {label}")
    print(f"{'='*60}")
    if os.path.exists(out_path):
        os.unlink(out_path)
    recv = subprocess.Popen(recv_cmd)
    time.sleep(1.5)
    send = subprocess.Popen(send_cmd)
    send.wait()
    recv.wait()
    if recv.returncode != 0 or send.returncode != 0:
        print(f"[!] FAILED  recv={recv.returncode}  send={send.returncode}")
        return False
    orig = sha256(TEST)
    rcvd = sha256(out_path)
    if orig == rcvd:
        print(f"[+] PASS  SHA-256={orig}")
        return True
    else:
        print(f"[!] HASH MISMATCH\n  orig={orig}\n  rcvd={rcvd}")
        return False

ok_a = run_approach(
    "Approach A – Mutual TLS (mTLS)",
    ["python3", os.path.join(BASE,"approach-a-mtls","receiver.py"), os.path.join(BASE,"received_a.bin")],
    ["python3", os.path.join(BASE,"approach-a-mtls","sender.py"),   TEST],
    os.path.join(BASE,"received_a.bin"),
)

time.sleep(1)

ok_b = run_approach(
    "Approach B – App-Layer Encrypted Envelope (X25519 + ChaCha20-Poly1305)",
    ["python3", os.path.join(BASE,"approach-b-envelope","receiver.py"), os.path.join(BASE,"received_b.bin")],
    ["python3", os.path.join(BASE,"approach-b-envelope","sender.py"),   TEST],
    os.path.join(BASE,"received_b.bin"),
)

print(f"\n{'='*60}")
print(f"  Approach A: {'PASS' if ok_a else 'FAIL'}")
print(f"  Approach B: {'PASS' if ok_b else 'FAIL'}")
print(f"{'='*60}")
sys.exit(0 if ok_a and ok_b else 1)
