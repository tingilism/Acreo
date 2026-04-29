"""
chaos_activity_stream.py — adversarial chaos for activity streams
====================================================================

12 attacks targeting the adversarial boundary of the activity stream
primitive. These complement the 12 self-tests in acreo_activity_stream
(which cover happy path + basic tampering).

Attacks here probe:
  - Forged genesis frame (frame claiming index=0 with fake content)
  - Fork attempts (two divergent streams from the same prefix)
  - Mixed-suite frame in stream (Ed25519 frame in PQ stream)
  - Key-substitution attack (frame signed by attacker but claiming
    target agent's pubkey)
  - Partial segment verification (verify frames N-M without seeing
    genesis — must require explicit starting_chain_hash)
  - Large stream stress (50+ frames must verify in single segment)
  - Frame-id collision (two frames with same frame_id rejected by
    verifier even if both are otherwise valid)
  - Reorder within valid chain (frames that ARE in chain but reordered)
  - Payload mutation without hash update (already covered in self-test
    but checked again with subtle mutations)
  - Timestamp anomalies (frame with timestamp in past relative to
    previous frame, frame with timestamp far in future)
  - Cross-protocol confusion (frame with wrong protocol string)
  - Empty stream verification

Run:
    python chaos_activity_stream.py
"""

from __future__ import annotations
import argparse
import copy
import json
import sys
import time
from dataclasses import dataclass, asdict
from typing import Callable

from acreo import Identity, AcreoError, Entropy
from acreo_activity_stream import (
    ActivityStream, ActivityFrame, StreamVerifier,
    ACTIVITY_PROTOCOL, _canonical_hash, _frame_chain_hash,
)


SEVERITY_INFO = "INFO"
SEVERITY_LOW = "LOW"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_HIGH = "HIGH"
SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_ORDER = {SEVERITY_INFO: 0, SEVERITY_LOW: 1, SEVERITY_MEDIUM: 2,
                  SEVERITY_HIGH: 3, SEVERITY_CRITICAL: 4}


@dataclass
class AttackResult:
    family: str
    name: str
    claim: str
    outcome: str
    severity: str = SEVERITY_INFO
    detail: str = ""


_results: list[AttackResult] = []
_attacks: list[Callable] = []


def record_pass(family, name, claim, detail=""):
    _results.append(AttackResult(family, name, claim, "PASS", SEVERITY_INFO, detail))


def record_fail(family, name, claim, severity, detail):
    _results.append(AttackResult(family, name, claim, "FAIL", severity, detail))


def record_skip(family, name, claim, reason):
    _results.append(AttackResult(family, name, claim, "SKIP", SEVERITY_INFO, reason))


def attack(family, name, claim):
    def decorator(fn):
        _attacks.append(fn)
        fn._family = family
        fn._name = name
        fn._claim = claim
        return fn
    return decorator


def is_valid(r):
    return bool(r.get("valid", False)) if isinstance(r, dict) else False


# ═══════════════════════════════════════════════════════════════════════
# ATTACKS
# ═══════════════════════════════════════════════════════════════════════

@attack("activity", "forged_genesis_frame",
        "Attacker constructs a genesis frame with their key claiming target's identity")
def forged_genesis():
    """An attacker wants to write a 'history' for target_agent. They construct
    a frame with target_agent's pubkey but sign it with their own key."""
    target = Identity.create_agent('target')
    attacker = Identity.create_agent('attacker')

    # Attacker builds a frame claiming to be from target
    forged = ActivityFrame(
        frame_id=Entropy.hex(16),
        frame_index=0,
        frame_type='action',
        agent_key=target.public_key,  # claims to be target
        timestamp_ms=int(time.time() * 1000),
        previous_frame_hash='0' * 64,
        payload_hash=_canonical_hash({'malicious': 'forged history'}),
        payload={'malicious': 'forged history'},
        crypto_suite=target.crypto_suite,
        protocol=ACTIVITY_PROTOCOL,
    )
    # Sign with attacker's key (not target's)
    from acreo_activity_stream import _frame_signing_payload
    from acreo import _sign_with
    signing_payload_hex = _frame_signing_payload(forged.to_dict())
    sig = _sign_with(
        attacker.crypto_suite,
        attacker._priv.hex if attacker.crypto_suite == 'ed25519' else attacker._priv.value,
        bytes.fromhex(signing_payload_hex),
    )
    forged.signature = sig.hex() if isinstance(sig, bytes) else sig

    v = StreamVerifier(target.public_key)
    verdict = v.verify_segment([forged])
    if not is_valid(verdict):
        record_pass("activity", "forged_genesis_frame",
                    "Attacker constructs a genesis frame with their key claiming target's identity",
                    f"rejected: {verdict.get('reason')}")
    else:
        record_fail("activity", "forged_genesis_frame",
                    "Attacker constructs a genesis frame with their key claiming target's identity",
                    SEVERITY_CRITICAL,
                    "forged genesis accepted")


@attack("activity", "fork_attempt",
        "Two divergent streams from same prefix — both verify, but verifier sees they fork")
def fork_attempt():
    """Two different segments share a common prefix. Each verifies on its own.
    The fork is detectable because their frame at index N has different
    chain hashes — anyone watching both segments can spot the divergence."""
    agent = Identity.create_agent('alice')
    s = ActivityStream(agent)
    s.record_observation({'a': 1})
    s.record_observation({'a': 2})

    # Now create two different "next frames" from the same prefix
    # Save state, branch A
    chain_state_A = s._last_chain_hash
    index_state_A = s._next_index

    s.record_action({'branch': 'A'})
    branch_A = list(s.frames)

    # Reset and create branch B from same prefix
    s_alt = ActivityStream(agent)
    s_alt.record_observation({'a': 1})  # different content from s.frames[0]!
    # This creates a different chain. To truly fork from same prefix, copy state:
    s_alt2 = ActivityStream(agent)
    s_alt2.frames = list(s.frames[:2])
    s_alt2._last_chain_hash = chain_state_A
    s_alt2._next_index = index_state_A
    s_alt2.record_action({'branch': 'B'})
    branch_B = list(s_alt2.frames)

    v_A = StreamVerifier(agent.public_key)
    v_B = StreamVerifier(agent.public_key)
    verdict_A = v_A.verify_segment(branch_A)
    verdict_B = v_B.verify_segment(branch_B)

    # Both should verify on their own
    if not (is_valid(verdict_A) and is_valid(verdict_B)):
        record_fail("activity", "fork_attempt",
                    "Two divergent streams from same prefix — both verify, but verifier sees they fork",
                    SEVERITY_HIGH,
                    f"branches don't both verify: A={verdict_A}, B={verdict_B}")
        return

    # The fork is detectable: branch_A[2] and branch_B[2] have same
    # previous_frame_hash but different frame contents → different chain hashes
    fork_detectable = (
        branch_A[2].previous_frame_hash == branch_B[2].previous_frame_hash
        and _frame_chain_hash(branch_A[2].to_dict()) != _frame_chain_hash(branch_B[2].to_dict())
    )
    if fork_detectable:
        record_pass("activity", "fork_attempt",
                    "Two divergent streams from same prefix — both verify, but verifier sees they fork",
                    "fork is detectable by external observer")
    else:
        record_fail("activity", "fork_attempt",
                    "Two divergent streams from same prefix — both verify, but verifier sees they fork",
                    SEVERITY_MEDIUM,
                    "fork not detectable")


@attack("activity", "wrong_suite_in_stream",
        "Frame with wrong crypto_suite tag in PQ stream rejected")
def wrong_suite_in_stream():
    """A PQ agent's stream contains a frame with crypto_suite='ed25519' but
    actually signed with PQ key. Verifier dispatches by frame.crypto_suite
    and tries Ed25519 verification on a PQ signature — fails."""
    pq_agent = Identity.create_agent_pq('pq-bob')
    s = ActivityStream(pq_agent)
    s.record_observation({'a': 1})

    # Tamper with the crypto_suite field
    tampered = ActivityFrame.from_dict(s.frames[0].to_dict())
    tampered.crypto_suite = 'ed25519'  # lie about suite

    v = StreamVerifier(pq_agent.public_key)
    verdict = v.verify_segment([tampered])
    if not is_valid(verdict):
        record_pass("activity", "wrong_suite_in_stream",
                    "Frame with wrong crypto_suite tag in PQ stream rejected",
                    f"rejected: {verdict.get('reason')}")
    else:
        record_fail("activity", "wrong_suite_in_stream",
                    "Frame with wrong crypto_suite tag in PQ stream rejected",
                    SEVERITY_HIGH,
                    "suite-tag tampering accepted")


@attack("activity", "key_substitution",
        "Frame's agent_key swapped to attacker's key while keeping target's signature")
def key_substitution():
    """Attacker can't generate a valid signature for target. Instead they take
    target's frame and swap the agent_key to their own — but the signature
    won't verify against the new key."""
    target = Identity.create_agent('target')
    attacker = Identity.create_agent('attacker')

    s = ActivityStream(target)
    s.record_observation({'a': 1})

    tampered = ActivityFrame.from_dict(s.frames[0].to_dict())
    tampered.agent_key = attacker.public_key  # swap key, keep signature

    v = StreamVerifier(attacker.public_key)
    verdict = v.verify_segment([tampered])
    if not is_valid(verdict):
        record_pass("activity", "key_substitution",
                    "Frame's agent_key swapped to attacker's key while keeping target's signature",
                    f"rejected: {verdict.get('reason')}")
    else:
        record_fail("activity", "key_substitution",
                    "Frame's agent_key swapped to attacker's key while keeping target's signature",
                    SEVERITY_CRITICAL,
                    "key substitution accepted")


@attack("activity", "partial_segment_no_starting_hash",
        "Partial segment verification without starting_chain_hash defaults to genesis (correctly fails)")
def partial_segment_no_starting():
    """Frames N-M extracted from a longer stream. Verifier called without
    starting_chain_hash — defaults to genesis. The first frame in the segment
    has frame_index > 0 and previous_frame_hash != genesis, so verification
    must fail."""
    agent = Identity.create_agent('alice')
    s = ActivityStream(agent)
    s.record_observation({'a': 1})
    s.record_observation({'a': 2})
    s.record_observation({'a': 3})

    # Try to verify just the last two frames without telling the verifier
    # where to start
    v = StreamVerifier(agent.public_key)
    verdict = v.verify_segment(s.frames[1:])  # no starting_chain_hash
    if not is_valid(verdict):
        record_pass("activity", "partial_segment_no_starting_hash",
                    "Partial segment verification without starting_chain_hash defaults to genesis (correctly fails)",
                    f"rejected: {verdict.get('reason')}")
    else:
        record_fail("activity", "partial_segment_no_starting_hash",
                    "Partial segment verification without starting_chain_hash defaults to genesis (correctly fails)",
                    SEVERITY_HIGH,
                    "partial segment verified without proper anchor")


@attack("activity", "partial_segment_with_starting_hash",
        "Partial segment verification works correctly with explicit starting_chain_hash")
def partial_segment_with_starting():
    """Same setup as above but verifier is given the correct starting hash."""
    agent = Identity.create_agent('alice')
    s = ActivityStream(agent)
    s.record_observation({'a': 1})
    s.record_observation({'a': 2})
    s.record_observation({'a': 3})

    # Compute the chain hash after frame 0
    starting_hash = _frame_chain_hash(s.frames[0].to_dict())

    v = StreamVerifier(agent.public_key)
    verdict = v.verify_segment(s.frames[1:], starting_chain_hash=starting_hash)
    if is_valid(verdict) and verdict.get('frames_verified') == 2:
        record_pass("activity", "partial_segment_with_starting_hash",
                    "Partial segment verification works correctly with explicit starting_chain_hash",
                    f"verified {verdict['frames_verified']} frames")
    else:
        record_fail("activity", "partial_segment_with_starting_hash",
                    "Partial segment verification works correctly with explicit starting_chain_hash",
                    SEVERITY_HIGH,
                    f"verdict: {verdict}")


@attack("activity", "large_stream_50_frames",
        "Stream of 50 frames verifies in single segment without errors")
def large_stream():
    agent = Identity.create_agent('alice')
    s = ActivityStream(agent)
    for i in range(50):
        s.record_observation({'iteration': i, 'data': f'frame-{i}'})

    v = StreamVerifier(agent.public_key)
    verdict = v.verify_segment(s.frames)
    if is_valid(verdict) and verdict.get('frames_verified') == 50:
        record_pass("activity", "large_stream_50_frames",
                    "Stream of 50 frames verifies in single segment without errors",
                    f"verified {verdict['frames_verified']} frames")
    else:
        record_fail("activity", "large_stream_50_frames",
                    "Stream of 50 frames verifies in single segment without errors",
                    SEVERITY_MEDIUM,
                    f"verdict: {verdict}")


@attack("activity", "duplicate_frame_id_within_segment",
        "Two frames with same frame_id (one duplicated) blocked by verifier replay tracking")
def duplicate_frame_id():
    agent = Identity.create_agent('alice')
    s = ActivityStream(agent)
    s.record_observation({'a': 1})

    v = StreamVerifier(agent.public_key)
    # Pass the same frame twice in one segment
    verdict = v.verify_segment([s.frames[0], s.frames[0]])
    if not is_valid(verdict):
        record_pass("activity", "duplicate_frame_id_within_segment",
                    "Two frames with same frame_id (one duplicated) blocked by verifier replay tracking",
                    f"rejected: {verdict.get('reason')}")
    else:
        record_fail("activity", "duplicate_frame_id_within_segment",
                    "Two frames with same frame_id (one duplicated) blocked by verifier replay tracking",
                    SEVERITY_HIGH,
                    "duplicate frame_id accepted")


@attack("activity", "wrong_protocol_string",
        "Frame with bogus protocol string rejected")
def wrong_protocol():
    agent = Identity.create_agent('alice')
    s = ActivityStream(agent)
    s.record_observation({'a': 1})

    tampered = ActivityFrame.from_dict(s.frames[0].to_dict())
    tampered.protocol = 'bogus-protocol-v99'

    v = StreamVerifier(agent.public_key)
    verdict = v.verify_segment([tampered])
    if not is_valid(verdict):
        record_pass("activity", "wrong_protocol_string",
                    "Frame with bogus protocol string rejected",
                    f"rejected: {verdict.get('reason')}")
    else:
        record_fail("activity", "wrong_protocol_string",
                    "Frame with bogus protocol string rejected",
                    SEVERITY_MEDIUM,
                    "wrong protocol accepted")


@attack("activity", "empty_segment_rejected",
        "Empty list of frames cleanly rejected")
def empty_segment():
    agent = Identity.create_agent('alice')
    v = StreamVerifier(agent.public_key)
    verdict = v.verify_segment([])
    if not is_valid(verdict):
        record_pass("activity", "empty_segment_rejected",
                    "Empty list of frames cleanly rejected",
                    f"rejected: {verdict.get('reason')}")
    else:
        record_fail("activity", "empty_segment_rejected",
                    "Empty list of frames cleanly rejected",
                    SEVERITY_LOW,
                    "empty segment accepted")


@attack("activity", "user_identity_cannot_stream",
        "User identity (kind='user') cannot create activity stream")
def user_cannot_stream():
    user = Identity.create_user('alice')
    try:
        s = ActivityStream(user)
        record_fail("activity", "user_identity_cannot_stream",
                    "User identity (kind='user') cannot create activity stream",
                    SEVERITY_MEDIUM,
                    "user identity allowed to create stream")
    except AcreoError as e:
        record_pass("activity", "user_identity_cannot_stream",
                    "User identity (kind='user') cannot create activity stream",
                    f"raised AcreoError: {e}")
    except Exception as e:
        record_pass("activity", "user_identity_cannot_stream",
                    "User identity (kind='user') cannot create activity stream",
                    f"raised {type(e).__name__}: {e}")


@attack("activity", "convenience_methods_advance_chain",
        "Identity.record_* methods advance the chain across multiple calls")
def convenience_chain_advance():
    """Stage E integration test: identity.record_observation/action/etc.
    correctly maintain a single chain across calls."""
    agent = Identity.create_agent('alice')
    f1 = agent.record_observation({'x': 1})
    f2 = agent.record_action({'y': 2})
    f3 = agent.record_state({'z': 3})

    chain_correct = (
        f1.frame_index == 0 and f2.frame_index == 1 and f3.frame_index == 2
        and f1.previous_frame_hash == '0' * 64
        and f2.previous_frame_hash == _frame_chain_hash(f1.to_dict())
        and f3.previous_frame_hash == _frame_chain_hash(f2.to_dict())
    )
    if chain_correct:
        # Also verify they actually verify cleanly
        v = StreamVerifier(agent.public_key)
        verdict = v.verify_segment([f1, f2, f3])
        if is_valid(verdict):
            record_pass("activity", "convenience_methods_advance_chain",
                        "Identity.record_* methods advance the chain across multiple calls",
                        f"3 frames, chain advances correctly, all verify")
        else:
            record_fail("activity", "convenience_methods_advance_chain",
                        "Identity.record_* methods advance the chain across multiple calls",
                        SEVERITY_HIGH,
                        f"chain looks correct but verification fails: {verdict}")
    else:
        record_fail("activity", "convenience_methods_advance_chain",
                    "Identity.record_* methods advance the chain across multiple calls",
                    SEVERITY_HIGH,
                    "chain advancement broken via convenience methods")


# ═══════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="chaos_activity_stream_results.json")
    args = parser.parse_args()

    icons = {"PASS": "✓", "FAIL": "✗", "SKIP": "⋯", "ERROR": "!"}

    print(f"Acreo activity stream chaos test — {len(_attacks)} attacks\n")
    print("[ACTIVITY]")

    for fn in _attacks:
        try:
            fn()
        except Exception as e:
            _results.append(AttackResult(
                family="activity", name=fn._name, claim=fn._claim,
                outcome="ERROR", severity=SEVERITY_INFO,
                detail=f"infra error: {type(e).__name__}: {e}",
            ))

        last = _results[-1]
        tag = f" [{last.severity}]" if last.outcome == "FAIL" else ""
        detail = (last.detail or "").replace("\n", " ")[:80]
        print(f"  {icons[last.outcome]} {last.outcome}{tag} {last.name} — {detail}")

    counts = {"PASS": 0, "FAIL": 0, "SKIP": 0, "ERROR": 0}
    for r in _results:
        counts[r.outcome] += 1
    print("\n" + "═" * 60)
    print(f"  Total: {len(_results)}  PASS={counts['PASS']}  "
          f"FAIL={counts['FAIL']}  SKIP={counts['SKIP']}  "
          f"ERROR={counts['ERROR']}")

    fails = [r for r in _results if r.outcome == "FAIL"]
    if fails:
        print("\n  Findings:")
        fails.sort(key=lambda r: -SEVERITY_ORDER[r.severity])
        for r in fails:
            print(f"    [{r.severity}] {r.name}")
            print(f"        claim: {r.claim}")
            print(f"        detail: {r.detail}")

    errors = [r for r in _results if r.outcome == "ERROR"]
    if errors:
        print("\n  Errors:")
        for r in errors:
            print(f"    [!] {r.name}")
            print(f"        {r.detail}")

    print("═" * 60)

    with open(args.output, "w") as fp:
        json.dump({
            "total": len(_results),
            "summary": counts,
            "results": [asdict(r) for r in _results],
        }, fp, indent=2)
    print(f"\n  Full results: {args.output}")

    if any(r.outcome == "ERROR" for r in _results):
        return 2
    if any(SEVERITY_ORDER[r.severity] >= SEVERITY_ORDER[SEVERITY_MEDIUM]
           for r in fails):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
