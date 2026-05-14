# AI Usage Notes — CMPE 272 Final Q10

## Tool used
Claude (claude-sonnet-4-6) via Claude Code CLI.

---

## What Claude wrote end-to-end

- The skeleton structure of both sender and receiver scripts (socket setup,
  the `recv_exact` / framing helpers, the overall while-True read loop).
- The HKDF key derivation and ChaCha20-Poly1305 encrypt/decrypt calls in
  Approach B (I verified each call against the `cryptography` library docs).
- The first draft of README.md and DESIGN.md.

## Where I directed Claude, not the other way around

- I chose the two approaches (mTLS vs. app-layer X25519) myself before
  asking Claude to scaffold them. Claude suggested also considering SCP or
  rsync-over-SSH; I rejected those because they are not hand-assembled
  protocols and would not demonstrate understanding of the primitives.
- I specified the nonce construction (`counter || zeros`) explicitly after
  Claude's first draft used `os.urandom(12)` per chunk, which is fine for
  small volumes but risks collision at scale (birthday bound on 96-bit
  random nonces is ~2^48 chunks). A deterministic counter is safer here.
- I required that the receiver write to a `.tmp` file and only rename after
  the hash check. Claude's first draft wrote directly to the final filename.
  Writing to the final filename before verification is a Common Pitfall
  listed in the exam brief — I caught it and corrected it.

## One thing Claude did better than I expected

Claude correctly identified the TLS close_notify race in Approach A (sender
closes the TLS socket while receiver is still reading buffered chunks) and
suggested adding a 1-byte ACK from receiver to sender to prevent the race.
This is the right solution — it keeps the TLS connection open until the
receiver has confirmed it is done reading.

## One thing Claude did worse than I expected

Claude's first Approach B handshake sent raw 32-byte keys with no framing,
relying on fixed-offset parsing. This is brittle and would break silently if
the key size ever changed. I changed it to a length-framed message (4-byte
length prefix before every message) so parsing is explicit throughout.

## Other AI tools used alongside Claude

No other AI tools were used. Claude Code (CLI) was the sole AI assistant throughout
this assessment — for scaffolding, code review, and threat-table generation.

---

## Security choices I verified personally

1. **No nonce reuse**: Each chunk uses `counter || 0x00*8` as its nonce.
   The counter increments every chunk. The final hash message uses
   `counter + 1`. I traced through the code to confirm no two messages
   share a nonce under the same session key.

2. **AEAD, not bare encryption**: Both approaches use authenticated
   encryption (AES-GCM via TLS; ChaCha20-Poly1305 explicitly). Neither
   uses raw AES-CBC or CTR without a MAC.

3. **Fail-closed on verification failure**: Both receivers call
   `os.unlink(tmp_path)` before `sys.exit(1)` if the hash does not match.
   The partial `.tmp` file is always deleted.

4. **No secrets in source**: Private keys and certificates are loaded from
   files at runtime; no key material appears in source code.

5. **Mutual authentication**: Approach A — both sides present X.509 certs
   (`CERT_REQUIRED` on server, client also loads and verifies CA). Approach B
   — both sides sign their ephemeral public keys with Ed25519 and verify the
   peer's signature against a pre-loaded public key before any data flows.
