"""
acreo_sealed_pq.py — post-quantum sealed messaging
=====================================================

Stage D-2 of the Mindzi-incorporation work. Provides sealed sender
encryption between two identities using ML-KEM-768 + ChaCha20-Poly1305.

Same shape as acreo_sealed.py (X25519-based) but post-quantum-secure.
Sender encapsulates a shared secret to recipient's ML-KEM-768 public
key; recipient decapsulates with their ML-KEM-768 private key.
ChaCha20-Poly1305 encrypts the actual message under a key derived from
the shared secret.

WHAT THIS PROTECTS:
  External observers cannot decrypt the sealed message. The encryption
  is post-quantum-secure: a sufficiently powerful quantum computer
  cannot break ML-KEM-768 (lattice-based) the way it would break X25519
  (elliptic-curve).

WHAT THIS DOES NOT DO:
  - Authenticate the sender. Anyone with the recipient's public key can
    seal a message to them. If you need authenticated sealed messages,
    sign the plaintext before sealing.
  - Provide forward secrecy beyond per-message KEM ephemerality.
    Compromise of recipient's secret key would expose all past messages.

CRYPTOGRAPHIC CONSTRUCTION:
  - ML-KEM-768 KEM (NIST FIPS 203) for key encapsulation
  - HKDF-SHA256 to derive symmetric key from the shared secret
  - ChaCha20-Poly1305 AEAD for the actual encryption
  - The KEM ciphertext (1088B) is bundled with the encrypted payload
  - AD binds ciphertext to KEM ciphertext + protocol version

  Performance (kyber-py 1.2.0): keygen=4ms encaps=4ms decaps=6ms
  Sizes: pk=1184B sk=2400B kem_ct=1088B shared=32B

  Note: kyber-py is an educational implementation, not constant-time.
  Suitable for research and prototyping. Production use requires a
  constant-time port. See README for details.

USAGE:
    from acreo_sealed_pq import SealedMessagePQ, keygen

    priv_hex, pub_hex = keygen()
    sealed = SealedMessagePQ.seal(pub_hex, b"hello bob")
    plaintext = SealedMessagePQ.unseal(priv_hex, sealed)
"""

from __future__ import annotations
import base64
import json
import secrets

from kyber_py.ml_kem import ML_KEM_768
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag


SEALED_PQ_PROTOCOL = "acreo-sealed-pq-v1"
KDF_INFO = b"acreo-sealed-pq-message-key-v1"

# ML-KEM-768 sizes (bytes)
ML_KEM_768_PK_SIZE = 1184
ML_KEM_768_SK_SIZE = 2400
ML_KEM_768_CT_SIZE = 1088


def _derive_key(shared_secret: bytes, kem_ct: bytes) -> bytes:
    """HKDF-SHA256 to derive symmetric key from KEM shared secret.

    Salt is the KEM ciphertext, binding the derived key to this specific
    encapsulation.
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=kem_ct,
        info=KDF_INFO,
    ).derive(shared_secret)


def keygen() -> tuple[str, str]:
    """Generate a fresh ML-KEM-768 keypair, returned as hex.

    Returns:
        (priv_hex, pub_hex) where priv is 2400 bytes and pub is 1184 bytes.
    """
    pub, priv = ML_KEM_768.keygen()
    return (priv.hex(), pub.hex())


class SealedMessagePQ:
    """Encrypted message addressed to a specific PQ recipient.

    Wire format (base64-encoded JSON envelope):
      - protocol: version string
      - kem_ct: ML-KEM-768 ciphertext (1088 bytes)
      - nonce: ChaCha20-Poly1305 nonce (12 bytes)
      - ciphertext: encrypted + authenticated payload
    """

    @staticmethod
    def seal(recipient_pub_hex: str, payload: bytes) -> str:
        """Encrypt payload to a PQ recipient. Returns base64-encoded JSON blob."""
        if not isinstance(payload, (bytes, bytearray)):
            raise TypeError(f"payload must be bytes, got {type(payload).__name__}")

        recipient_pub = bytes.fromhex(recipient_pub_hex)
        if len(recipient_pub) != ML_KEM_768_PK_SIZE:
            raise ValueError(
                f"ML-KEM-768 public key must be {ML_KEM_768_PK_SIZE} bytes, "
                f"got {len(recipient_pub)}")

        # KEM encapsulation: produces (shared_secret, kem_ct)
        # Only the holder of the matching secret key can recover shared_secret
        shared_secret, kem_ct = ML_KEM_768.encaps(recipient_pub)

        key = _derive_key(shared_secret, kem_ct)

        # Encrypt with ChaCha20-Poly1305
        chacha = ChaCha20Poly1305(key)
        nonce = secrets.token_bytes(12)
        ad = kem_ct + SEALED_PQ_PROTOCOL.encode()
        ct = chacha.encrypt(nonce, bytes(payload), ad)

        envelope = {
            "protocol": SEALED_PQ_PROTOCOL,
            "kem_ct": base64.b64encode(kem_ct).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ct).decode(),
        }
        return base64.b64encode(json.dumps(envelope).encode()).decode()

    @staticmethod
    def unseal(recipient_priv_hex: str, sealed_blob: str) -> bytes:
        """Decrypt sealed message using recipient's PQ private key."""
        try:
            envelope = json.loads(base64.b64decode(sealed_blob))
        except Exception as e:
            raise ValueError(f"malformed sealed blob: {e}")

        if envelope.get("protocol") != SEALED_PQ_PROTOCOL:
            raise ValueError(
                f"unknown protocol: {envelope.get('protocol')!r}")

        recipient_priv = bytes.fromhex(recipient_priv_hex)
        if len(recipient_priv) != ML_KEM_768_SK_SIZE:
            raise ValueError(
                f"ML-KEM-768 secret key must be {ML_KEM_768_SK_SIZE} bytes, "
                f"got {len(recipient_priv)}")

        kem_ct = base64.b64decode(envelope["kem_ct"])
        if len(kem_ct) != ML_KEM_768_CT_SIZE:
            raise ValueError(
                f"ML-KEM-768 ciphertext must be {ML_KEM_768_CT_SIZE} bytes, "
                f"got {len(kem_ct)}")

        try:
            shared_secret = ML_KEM_768.decaps(recipient_priv, kem_ct)
        except Exception as e:
            raise ValueError(f"KEM decapsulation failed: {e}")

        key = _derive_key(shared_secret, kem_ct)

        chacha = ChaCha20Poly1305(key)
        nonce = base64.b64decode(envelope["nonce"])
        ct = base64.b64decode(envelope["ciphertext"])
        ad = kem_ct + SEALED_PQ_PROTOCOL.encode()

        try:
            return chacha.decrypt(nonce, ct, ad)
        except InvalidTag:
            raise ValueError("authentication failed — wrong recipient or tampered")


# ─── Self-test ────────────────────────────────────────────────────────

def _self_test() -> int:
    print("acreo_sealed_pq self-test")
    print("─" * 40)

    results = []

    def check(name, fn):
        try:
            ok = fn()
        except Exception as e:
            print(f"  ✗ {name}: {type(e).__name__}: {e}")
            results.append(False)
            return
        if ok:
            print(f"  ✓ {name}")
            results.append(True)
        else:
            print(f"  ✗ {name}: returned False")
            results.append(False)

    recipient_priv_hex, recipient_pub_hex = keygen()
    other_priv_hex, _ = keygen()

    msg = b"hello, this is a sealed PQ test message"
    sealed = SealedMessagePQ.seal(recipient_pub_hex, msg)
    check("round-trip decrypts to original",
          lambda: SealedMessagePQ.unseal(recipient_priv_hex, sealed) == msg)

    sealed2 = SealedMessagePQ.seal(recipient_pub_hex, msg)
    check("two seals of same plaintext differ on the wire",
          lambda: sealed != sealed2)
    check("both decrypt to same plaintext",
          lambda: (SealedMessagePQ.unseal(recipient_priv_hex, sealed) ==
                   SealedMessagePQ.unseal(recipient_priv_hex, sealed2) == msg))

    def wrong_recipient_fails():
        try:
            SealedMessagePQ.unseal(other_priv_hex, sealed)
            return False
        except ValueError:
            return True
    check("wrong recipient rejected", wrong_recipient_fails)

    def tampered_fails():
        try:
            tampered = json.loads(base64.b64decode(sealed))
            ct = base64.b64decode(tampered["ciphertext"])
            ct = bytes([ct[0] ^ 0xFF]) + ct[1:]
            tampered["ciphertext"] = base64.b64encode(ct).decode()
            blob = base64.b64encode(json.dumps(tampered).encode()).decode()
            SealedMessagePQ.unseal(recipient_priv_hex, blob)
            return False
        except ValueError:
            return True
    check("tampered ciphertext rejected", tampered_fails)

    sealed_empty = SealedMessagePQ.seal(recipient_pub_hex, b"")
    check("empty payload round-trips",
          lambda: SealedMessagePQ.unseal(recipient_priv_hex, sealed_empty) == b"")

    big = secrets.token_bytes(64 * 1024)
    sealed_big = SealedMessagePQ.seal(recipient_pub_hex, big)
    check("64KB payload round-trips",
          lambda: SealedMessagePQ.unseal(recipient_priv_hex, sealed_big) == big)

    def non_bytes_rejected():
        try:
            SealedMessagePQ.seal(recipient_pub_hex, "string not bytes")  # type: ignore
            return False
        except TypeError:
            return True
    check("non-bytes payload rejected", non_bytes_rejected)

    def wrong_size_pub_rejected():
        try:
            SealedMessagePQ.seal("00" * 64, b"hello")
            return False
        except ValueError:
            return True
    check("wrong-size pubkey rejected", wrong_size_pub_rejected)

    def malformed_rejected():
        try:
            SealedMessagePQ.unseal(recipient_priv_hex, "not-base64-json-anything")
            return False
        except ValueError:
            return True
    check("malformed sealed blob rejected", malformed_rejected)

    print("─" * 40)
    passed = sum(results)
    total = len(results)
    print(f"  {passed}/{total} passed")
    return 0 if passed == total else 1


if __name__ == "__main__":
    import sys
    sys.exit(_self_test())
