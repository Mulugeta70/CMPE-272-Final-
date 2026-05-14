#!/usr/bin/env python3
"""
Threat Test 2 – Kill the connection mid-transfer.
Verifies the receiver does NOT keep a partial file as if it were complete.
"""

import os, subprocess, sys, time, signal

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SMALL = os.path.join(BASE, "test_500mb.bin")

def run_kill_test(label, recv_cmd, send_cmd, out_path, kill_after=2.0):
    print(f"\n{'='*60}")
    print(f"  {label}")
    print(f"{'='*60}")

    if os.path.exists(out_path):
        os.unlink(out_path)
    if os.path.exists(out_path + ".tmp"):
        os.unlink(out_path + ".tmp")

    recv = subprocess.Popen(recv_cmd, stderr=subprocess.STDOUT)
    time.sleep(1.5)
    send = subprocess.Popen(send_cmd, stderr=subprocess.STDOUT)

    time.sleep(kill_after)
    print(f"[*] Killing sender after {kill_after}s (mid-transfer)...")
    send.kill()
    send.wait()
    recv.wait(timeout=5)

    if os.path.exists(out_path):
        print("[!] FAIL – partial file kept as final output!")
    elif os.path.exists(out_path + ".tmp"):
        print("[!] FAIL – .tmp file left behind (should have been deleted)!")
    else:
        print("[+] PASS – no output file; no .tmp file; receiver failed safely")

run_kill_test(
    "APPROACH A – Kill connection mid-transfer",
    ["python3", os.path.join(BASE,"approach-a-mtls","receiver.py"),
     os.path.join(BASE,"killed_out_a.bin")],
    ["python3", os.path.join(BASE,"approach-a-mtls","sender.py"), SMALL],
    os.path.join(BASE,"killed_out_a.bin"),
    kill_after=1.0,
)

time.sleep(1)

run_kill_test(
    "APPROACH B – Kill connection mid-transfer",
    ["python3", os.path.join(BASE,"approach-b-envelope","receiver.py"),
     os.path.join(BASE,"killed_out_b.bin")],
    ["python3", os.path.join(BASE,"approach-b-envelope","sender.py"), SMALL],
    os.path.join(BASE,"killed_out_b.bin"),
    kill_after=1.0,
)
