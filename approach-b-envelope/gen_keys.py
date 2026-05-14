#!/usr/bin/env python3
"""Generate long-lived Ed25519 signing key pairs for sender and receiver."""

import os
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, PublicFormat,
)

os.makedirs("keys", exist_ok=True)

for role in ("sender", "receiver"):
    priv = Ed25519PrivateKey.generate()
    pub  = priv.public_key()

    with open(f"keys/{role}_signing.pem", "wb") as f:
        f.write(priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    with open(f"keys/{role}_signing_pub.pem", "wb") as f:
        f.write(pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))

    print(f"[+] {role}: keys/{role}_signing.pem  keys/{role}_signing_pub.pem")
