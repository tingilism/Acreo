"""
acreo_sealed.py — sealed messaging between Acreo identities
=============================================================

Stage C-1 of the Mindzi-incorporation work. Adds the ability for two
Acreo agents to exchange end-to-end encrypted messages without prior
shared state — sender uses recipient's public key, only recipient can
decrypt with their private key.

This is "sealed sender" semantics: the wire shows that *some* sender sent
*some* ciphertext to *this* recipient, but the contents are opaque to
anyone except the recipient. Doesn't authenticate the sender by default —
that's a deliberate choice. If you want sender authentication, sign the
plaintext before sealing it.

Cryptography:
  - X25519 ephemeral key agreement (sender generates fresh ephemeral keypair
    per message, derives shared secret with recipient's static public key)
  - HKDF-SHA256 to derive symmetric key from shared secret
  - ChaCha20-Poly1305 AEAD for the actual encryption
  - Ephemeral public key bundled with ciphertext so recipient can derive
    the same shared secret

This is a standard sealed-box construction. Same shape as libsodium's
crypto_box_seal but built from the cryptography library primitives that
Acreo already uses.

Usage:
    from acreo_sealed import SealedMessage

    # Sender side
    sealed = SealedMessage.seal(recipient_public_key_hex, b"hello bob")

    # Recipient side
    plaintext = SealedMessage.unseal(my_private_key_hex, sealed)
    assert plaintext == b"hello bob"

Integration with Acreo:
    Two methods to add to Identity (see apply_sealed_messaging.py):
      Identity.send(recipient_pub, payload) -> sealed_blob
      Identity.receive(sealed_blob) -> plaintext_bytes
"""

from __future__ import annotations
import base64
import json
import secrets
from dataclasses import dataclass
from typing import Union

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidTag


SEALED_PROTOCOL = "acreo-sealed-v1"
KDF_INFO = b"acreo-sealed-message-key-v1"


def _x25519_from_pub_hex(pub_hex: str) -> X25519PublicKey:
    """Load X25519 public key from hex-encoded raw bytes."""
    raw = bytes.fromhex(pub_hex)
    if len(raw) != 32:
        raise ValueError(f"X25519 public key must be 32 bytes, got {len(raw)}")
    return X25519PublicKey.from_public_bytes(raw)


def _x25519_from_priv_hex(priv_hex: str) -> X25519PrivateKey:
    """Load X25519 private key from hex-encoded raw bytes."""
    raw = bytes.fromhex(priv_hex)
    if len(raw) != 32:
        raise ValueError(f"X25519 private key must be 32 bytes, got {len(raw)}")
    return X25519PrivateKey.from_private_bytes(raw)


def _pub_to_hex(pub: X25519PublicKey) -> str:
    return pub.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


def _derive_key(shared_secret: bytes, ephemeral_pub: bytes,
                recipient_pub: bytes) -> bytes:
    """HKDF-SHA256 to derive symmetric key from ECDH output.

    Salt is the concatenation of both public keys so the derived key
    is bound to this specific (sender, recipient) ephemeral pair.
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=ephemeral_pub + recipient_pub,
        info=KDF_INFO,
    ).derive(shared_secret)


@dataclass
class SealedMessage:
    """Encrypted message addressed to a specific recipient.

    The wire format includes:
      - ephemeral_pub: the sender's ephemeral X25519 public key (32 bytes)
      - nonce: ChaCha20-Poly1305 nonce (12 bytes)
      - ciphertext: encrypted + authenticated payload
      - protocol: version string for forward compatibility

    Anyone can verify the message was encrypted to the expected recipient
    (by attempting to decrypt). The sender's identity is NOT included —
    if you need sender authentication, sign the plaintext before sealing.
    """

    @staticmethod
    def seal(recipient_pub_hex: str, payload: bytes) -> str:
        """Encrypt payload to recipient. Returns base64-encoded JSON blob."""
        if not isinstance(payload, (bytes, bytearray)):
            raise TypeError(f"payload must be bytes, got {type(payload).__name__}")

        recipient_pub = _x25519_from_pub_hex(recipient_pub_hex)
        recipient_pub_raw = bytes.fromhex(recipient_pub_hex)

        # Generate ephemeral keypair for this message
        ephemeral_priv = X25519PrivateKey.generate()
        ephemeral_pub = ephemeral_priv.public_key()
        ephemeral_pub_raw = ephemeral_pub.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

        # ECDH
        shared = ephemeral_priv.exchange(recipient_pub)
        key = _derive_key(shared, ephemeral_pub_raw, recipient_pub_raw)

        # Encrypt
        chacha = ChaCha20Poly1305(key)
        nonce = secrets.token_bytes(12)
        # Associated data binds the ciphertext to the ephemeral pub + recipient pub
        # so an attacker can't replay the ciphertext under different keys.
        ad = ephemeral_pub_raw + recipient_pub_raw + SEALED_PROTOCOL.encode()
        ct = chacha.encrypt(nonce, bytes(payload), ad)

        envelope = {
            "protocol": SEALED_PROTOCOL,
            "ephemeral_pub": ephemeral_pub_raw.hex(),
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ct).decode(),
        }
        return base64.b64encode(json.dumps(envelope).encode()).decode()

    @staticmethod
    def unseal(recipient_priv_hex: str, sealed_blob: str) -> bytes:
        """Decrypt sealed message using recipient's private key."""
        try:
            envelope = json.loads(base64.b64decode(sealed_blob))
        except Exception as e:
            raise ValueError(f"malformed sealed blob: {e}")

        if envelope.get("protocol") != SEALED_PROTOCOL:
            raise ValueError(
                f"unknown protocol: {envelope.get('protocol')!r}"
            )

        ephemeral_pub_hex = envelope["ephemeral_pub"]
        ephemeral_pub_raw = bytes.fromhex(ephemeral_pub_hex)
        ephemeral_pub = _x25519_from_pub_hex(ephemeral_pub_hex)

        recipient_priv = _x25519_from_priv_hex(recipient_priv_hex)
        recipient_pub_raw = recipient_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

        # ECDH (same shared secret as sender computed)
        shared = recipient_priv.exchange(ephemeral_pub)
        key = _derive_key(shared, ephemeral_pub_raw, recipient_pub_raw)

        chacha = ChaCha20Poly1305(key)
        nonce = base64.b64decode(envelope["nonce"])
        ct = base64.b64decode(envelope["ciphertext"])
        ad = ephemeral_pub_raw + recipient_pub_raw + SEALED_PROTOCOL.encode()

        try:
            return chacha.decrypt(nonce, ct, ad)
        except InvalidTag:
            raise ValueError("authentication failed — wrong recipient or tampered")


# ─── Test surface (run as script) ─────────────────────────────────────

def _self_test() -> int:
    """Quick self-test. Run as: python acreo_sealed.py"""
    print("acreo_sealed self-test")
    print("─" * 40)

    results = []

    def check(name, condition):
        try:
            ok = condition()
        except Exception as e:
            print(f"  ✗ {name}: raised {type(e).__name__}: {e}")
            results.append(False)
            return
        if ok:
            print(f"  ✓ {name}")
            results.append(True)
        else:
            print(f"  ✗ {name}: returned False")
            results.append(False)

    # Generate a recipient keypair to test against
    recipient_priv = X25519PrivateKey.generate()
    recipient_pub_hex = _pub_to_hex(recipient_priv.public_key())
    recipient_priv_hex = recipient_priv.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    ).hex()

    # Wrong recipient
    other_priv = X25519PrivateKey.generate()
    other_priv_hex = other_priv.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    ).hex()

    # 1. Round trip
    msg = b"hello, this is a sealed test message"
    sealed = SealedMessage.seal(recipient_pub_hex, msg)
    check("round-trip decrypts to original",
          lambda: SealedMessage.unseal(recipient_priv_hex, sealed) == msg)

    # 2. Two seals of the same message produce different ciphertexts (ephemeral key)
    sealed2 = SealedMessage.seal(recipient_pub_hex, msg)
    check("two seals of same plaintext differ on the wire",
          lambda: sealed != sealed2)
    check("both decrypt to same plaintext",
          lambda: (SealedMessage.unseal(recipient_priv_hex, sealed) ==
                   SealedMessage.unseal(recipient_priv_hex, sealed2) == msg))

    # 3. Wrong recipient can't decrypt
    def wrong_recipient_fails():
        try:
            SealedMessage.unseal(other_priv_hex, sealed)
            return False  # should have raised
        except ValueError:
            return True
    check("wrong recipient rejected", wrong_recipient_fails)

    # 4. Tampered ciphertext rejected
    def tampered_fails():
        try:
            tampered = json.loads(base64.b64decode(sealed))
            ct = base64.b64decode(tampered["ciphertext"])
            ct = bytes([ct[0] ^ 0xFF]) + ct[1:]
            tampered["ciphertext"] = base64.b64encode(ct).decode()
            blob = base64.b64encode(json.dumps(tampered).encode()).decode()
            SealedMessage.unseal(recipient_priv_hex, blob)
            return False
        except ValueError:
            return True
    check("tampered ciphertext rejected", tampered_fails)

    # 5. Empty payload works
    sealed_empty = SealedMessage.seal(recipient_pub_hex, b"")
    check("empty payload round-trips",
          lambda: SealedMessage.unseal(recipient_priv_hex, sealed_empty) == b"")

    # 6. Large payload works
    big = secrets.token_bytes(64 * 1024)
    sealed_big = SealedMessage.seal(recipient_pub_hex, big)
    check("64KB payload round-trips",
          lambda: SealedMessage.unseal(recipient_priv_hex, sealed_big) == big)

    # 7. Non-bytes payload rejected
    def non_bytes_rejected():
        try:
            SealedMessage.seal(recipient_pub_hex, "string not bytes")  # type: ignore
            return False
        except TypeError:
            return True
    check("non-bytes payload rejected", non_bytes_rejected)

    # 8. Malformed blob rejected
    def malformed_rejected():
        try:
            SealedMessage.unseal(recipient_priv_hex, "not-base64-json-anything")
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
