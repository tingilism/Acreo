"""
test_sealed.py — sealed messaging integration test
====================================================

Exercises Identity.send / Identity.receive across real Acreo identities.

The standalone acreo_sealed.py self-test verifies the cryptographic primitive
in isolation. This file verifies the integration: that the X25519 derivation
from Acreo identities is consistent, that the API works end-to-end, and that
a few edge cases that only matter inside the Acreo context behave correctly.

Run:
    python test_sealed.py
"""

import sys

try:
    from acreo import Acreo, AcreoError
except ImportError as e:
    print(f"FATAL: {e}", file=sys.stderr)
    print("Run from Acreo repo root after applying sealed messaging patches.",
          file=sys.stderr)
    sys.exit(2)


def run():
    print("\n  Sealed messaging integration test")
    print("  " + "─" * 50)

    a = Acreo()
    alice = a.create_user('alice')
    bob = a.create_user('bob')
    alice_bot = a.create_agent('alice-bot')
    bob_bot = a.create_agent('bob-bot')

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

    # 1. Each identity has a peer_key
    check("user has peer_key", lambda: bool(alice.peer_key))
    check("agent has peer_key", lambda: bool(alice_bot.peer_key))
    check("peer_key is 64 hex chars (32 bytes)",
          lambda: len(alice.peer_key) == 64)
    check("peer_key is deterministic across calls",
          lambda: alice.peer_key == alice.peer_key)

    # 2. Different identities have different peer keys
    check("different users have different peer keys",
          lambda: alice.peer_key != bob.peer_key)
    check("user and their agent have different peer keys",
          lambda: alice.peer_key != alice_bot.peer_key)

    # 3. Round trip: alice's bot sends to bob's bot
    msg = b"hello bob, this is alice's bot"
    sealed = alice_bot.send(bob_bot.peer_key, msg)
    check("alice's bot can send to bob's bot",
          lambda: bool(sealed))
    check("bob's bot can decrypt", lambda: bob_bot.receive(sealed) == msg)

    # 4. Wrong recipient can't decrypt
    def wrong_recipient_fails():
        try:
            alice_bot.receive(sealed)
            return False
        except ValueError:
            return True
    check("wrong recipient (alice's own bot) is rejected",
          wrong_recipient_fails)

    # 5. Two seals of same message produce different blobs (ephemeral key)
    sealed2 = alice_bot.send(bob_bot.peer_key, msg)
    check("two seals of same plaintext differ on the wire",
          lambda: sealed != sealed2)

    # 6. User → user sealed messaging works (not just bot-to-bot)
    direct_msg = b"alice to bob, direct"
    direct_sealed = alice.send(bob.peer_key, direct_msg)
    check("user can send sealed to another user",
          lambda: bob.receive(direct_sealed) == direct_msg)

    # 7. User can send to their own agent (intra-operator notification path)
    intra = b"operator alice notifies her bot"
    intra_sealed = alice.send(alice_bot.peer_key, intra)
    check("user can send sealed to own agent",
          lambda: alice_bot.receive(intra_sealed) == intra)

    # 8. Bot can send back to user (bot-reports-to-operator path)
    notify = b"bot reports back to alice"
    notify_sealed = alice_bot.send(alice.peer_key, notify)
    check("agent can send sealed back to user",
          lambda: alice.receive(notify_sealed) == notify)

    # 9. Empty payload works
    empty_sealed = alice_bot.send(bob_bot.peer_key, b"")
    check("empty payload round-trips",
          lambda: bob_bot.receive(empty_sealed) == b"")

    # 10. Non-bytes payload raises clear error
    def non_bytes_rejected():
        try:
            alice_bot.send(bob_bot.peer_key, "not bytes")
            return False
        except TypeError:
            return True
    check("non-bytes payload rejected with TypeError",
          non_bytes_rejected)

    # 11. Tampered ciphertext rejected
    def tampered_rejected():
        import json, base64
        envelope = json.loads(base64.b64decode(sealed))
        ct = base64.b64decode(envelope["ciphertext"])
        ct = bytes([ct[0] ^ 0xFF]) + ct[1:]
        envelope["ciphertext"] = base64.b64encode(ct).decode()
        bad = base64.b64encode(json.dumps(envelope).encode()).decode()
        try:
            bob_bot.receive(bad)
            return False
        except ValueError:
            return True
    check("tampered ciphertext rejected",
          tampered_rejected)

    # 12. Existing primitives still work (smoke test for regression)
    cred = a.delegate(alice, alice_bot, ['transact'], scope=['*'])
    ap = a.authorize(alice_bot, cred, 'transact', '*')
    rv = a.verify_action(ap, cred)
    check("existing authorize/verify still works after sealed integration",
          lambda: rv.get('valid') is True)

    print("  " + "─" * 50)
    passed = sum(results)
    total = len(results)
    print(f"  {passed}/{total} passed")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(run())
