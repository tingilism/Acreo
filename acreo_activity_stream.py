"""
acreo_activity_stream.py — verifiable agent activity recording
================================================================

Stage E of Acreo: agents produce continuous, hash-chained, signed
records of their observations, reasoning, actions, and state. Each
frame references the previous frame's hash so any modification to
the stream is detectable.

The pattern is similar to git's commit chain or certificate transparency
logs: append-only, hash-linked, cryptographically signed at each step.

WHAT THIS PROTECTS:
  - Tampering with any past frame breaks the hash chain
  - Inserting forged frames between real ones is detectable
  - Deleting frames in the middle is detectable (chain breaks)
  - Replay of frames blocked by frame_id tracking
  - Signature rebinds each frame to the agent's identity

WHAT THIS DOES NOT DO:
  - Doesn't prove the agent's claims about external reality are true
    (the agent could lie about what it observed). The signature only
    proves "this agent claimed this thing at this time" — not that
    the claim corresponds to truth.
  - Doesn't provide privacy by default (payloads are inline). For
    sensitive content, payloads can be sealed via acreo_sealed (Stage
    C-1) or acreo_sealed_pq (Stage D-2) before being added to a frame.
    The hash chain stays publicly verifiable; only the content is
    encrypted.
  - Doesn't provide distributed verification yet (v0.5 work). A single
    operator could still drop the entire stream. v0.5's validator
    network would consume these streams as the data layer.

FRAME TYPES:
  - 'observation': something the agent perceived (input, sensor data,
    received message)
  - 'reasoning': internal decision-making step (LLM call, rule firing,
    deliberation)
  - 'action': something the agent did externally (API call, transaction,
    output produced)
  - 'state': periodic snapshot of agent internal state (memory, beliefs,
    accumulated context)

USAGE:
    from acreo_activity_stream import ActivityStream, StreamVerifier

    stream = ActivityStream(agent_identity)
    stream.record_observation({'sensor': 'price', 'value': 67234.50})
    stream.record_reasoning({'thought': 'price below threshold, buying'})
    stream.record_action({'type': 'order', 'side': 'buy', 'qty': 10})

    # Later, anyone with the agent's pubkey can verify:
    verifier = StreamVerifier(agent_identity.public_key)
    verdict = verifier.verify_segment(stream.frames)
    assert verdict['valid']
"""

from __future__ import annotations
import hashlib
import json
import time
from dataclasses import dataclass, asdict, field
from typing import List, Dict, Optional, Any

# Reuse Acreo's cryptographic primitives
from acreo import (
    _sign_with, _verify_with, Entropy, AcreoError,
    Identity, ProtectedKey,
)


ACTIVITY_PROTOCOL = "acreo-activity-v1"

VALID_FRAME_TYPES = ('observation', 'reasoning', 'action', 'state')


def _canonical_hash(obj: Any) -> str:
    """Deterministic hash of any JSON-serializable object."""
    canonical = json.dumps(obj, sort_keys=True, separators=(',', ':')).encode()
    return hashlib.sha3_256(canonical).hexdigest()


def _frame_signing_payload(frame_dict: Dict) -> str:
    """Compute the canonical hash of a frame's content (excluding signature).

    This is what gets signed — and also what the next frame's
    previous_frame_hash will reference (along with the signature itself,
    so the hash chain captures both content and authenticity).
    """
    # Strip the signature field for signing computation
    payload = {k: v for k, v in frame_dict.items() if k != 'signature'}
    return _canonical_hash(payload)


def _frame_chain_hash(signed_frame_dict: Dict) -> str:
    """Compute the hash that the next frame will reference.

    Includes the signature so any tampering with either content
    or signature breaks the chain at the next frame.
    """
    return _canonical_hash(signed_frame_dict)


@dataclass
class ActivityFrame:
    """One signed frame in an agent's activity stream.

    The hash chain is established by `previous_frame_hash`. The first
    frame in a stream uses '0' * 64 as its previous_frame_hash (genesis).
    """
    frame_id: str             # unique random ID per frame
    frame_index: int          # monotonically increasing per agent
    frame_type: str           # one of VALID_FRAME_TYPES
    agent_key: str            # agent's public key (hex)
    timestamp_ms: int         # wall-clock at frame creation
    previous_frame_hash: str  # hash of previous signed frame (genesis = '0'*64)
    payload_hash: str         # hash of the payload content
    payload: Dict             # the actual content (or sealed/encrypted version)
    crypto_suite: str         # 'ed25519' or 'ml-dsa-65', for verification dispatch
    protocol: str = ACTIVITY_PROTOCOL
    signature: str = ''       # hex signature; set by ActivityStream.append

    def to_dict(self) -> Dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, d: Dict) -> 'ActivityFrame':
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


class ActivityStream:
    """Producer of an agent's activity stream.

    Tracks the hash chain state and produces signed frames. Each call
    to a record_* method appends a new frame to the stream and returns
    the signed frame.
    """

    GENESIS_HASH = '0' * 64

    def __init__(self, identity: Identity):
        if identity.kind != 'agent':
            raise AcreoError(
                f"only agent identities can produce activity streams "
                f"(got kind={identity.kind!r})")
        self.identity = identity
        self.frames: List[ActivityFrame] = []
        self._last_chain_hash = self.GENESIS_HASH
        self._next_index = 0

    def _append(self, frame_type: str, payload: Dict) -> ActivityFrame:
        if frame_type not in VALID_FRAME_TYPES:
            raise ValueError(
                f"frame_type must be one of {VALID_FRAME_TYPES}, "
                f"got {frame_type!r}")

        frame = ActivityFrame(
            frame_id=Entropy.hex(16),
            frame_index=self._next_index,
            frame_type=frame_type,
            agent_key=self.identity.public_key,
            timestamp_ms=int(time.time() * 1000),
            previous_frame_hash=self._last_chain_hash,
            payload_hash=_canonical_hash(payload),
            payload=payload,
            crypto_suite=self.identity.crypto_suite,
            protocol=ACTIVITY_PROTOCOL,
            signature='',  # filled in below
        )

        signing_payload_hex = _frame_signing_payload(frame.to_dict())
        # _sign_with takes priv as hex (Ed25519) or raw bytes (PQ)
        if self.identity.crypto_suite == 'ed25519':
            priv_arg = self.identity._priv.hex
        else:
            priv_arg = self.identity._priv.value
        signature = _sign_with(
            self.identity.crypto_suite,
            priv_arg,
            bytes.fromhex(signing_payload_hex),
        )
        # Normalize signature representation (PQ returns bytes, Ed25519 returns hex)
        if isinstance(signature, bytes):
            frame.signature = signature.hex()
        else:
            frame.signature = signature

        # Advance chain state using the signed frame
        self._last_chain_hash = _frame_chain_hash(frame.to_dict())
        self._next_index += 1
        self.frames.append(frame)
        return frame

    def record_observation(self, payload: Dict) -> ActivityFrame:
        """Record something the agent perceived."""
        return self._append('observation', payload)

    def record_reasoning(self, payload: Dict) -> ActivityFrame:
        """Record an internal reasoning step."""
        return self._append('reasoning', payload)

    def record_action(self, payload: Dict) -> ActivityFrame:
        """Record an action the agent took externally."""
        return self._append('action', payload)

    def record_state(self, payload: Dict) -> ActivityFrame:
        """Record a snapshot of the agent's internal state."""
        return self._append('state', payload)


class StreamVerifier:
    """Verifies an activity stream segment is unbroken and authentic.

    Tracks seen frame_ids to block replay. A single verifier instance
    can verify frames from multiple agents (frame.agent_key disambiguates).
    """

    def __init__(self, expected_agent_key: Optional[str] = None):
        """If expected_agent_key is set, all frames must match it.
        Otherwise, frames are verified against whatever agent_key they claim.
        """
        self.expected_agent_key = expected_agent_key
        self._seen_frame_ids: set = set()

    def verify_segment(self, frames: List[ActivityFrame],
                        starting_chain_hash: Optional[str] = None) -> Dict:
        """Verify a list of frames is a valid stream segment.

        starting_chain_hash:
          - None or '0'*64: segment must start from genesis
          - any other hex: segment continues from that hash

        Returns a verdict dict: {'valid': bool, 'reason': str, ...}
        """
        if not frames:
            return {'valid': False, 'reason': 'empty_segment'}

        expected_prev = starting_chain_hash or ActivityStream.GENESIS_HASH
        expected_index = frames[0].frame_index

        for i, frame in enumerate(frames):
            verdict = self._verify_one(frame, expected_prev, expected_index)
            if not verdict['valid']:
                verdict['failed_at_index'] = i
                return verdict
            expected_prev = _frame_chain_hash(frame.to_dict())
            expected_index = frame.frame_index + 1

        return {
            'valid': True,
            'frames_verified': len(frames),
            'final_chain_hash': expected_prev,
        }

    def _verify_one(self, frame: ActivityFrame,
                     expected_prev_hash: str,
                     expected_index: int) -> Dict:
        # Protocol check
        if frame.protocol != ACTIVITY_PROTOCOL:
            return {'valid': False, 'reason': f'unknown_protocol:{frame.protocol}'}

        # Agent key check
        if self.expected_agent_key and frame.agent_key != self.expected_agent_key:
            return {'valid': False, 'reason': 'wrong_agent_key'}

        # Replay check
        if frame.frame_id in self._seen_frame_ids:
            return {'valid': False, 'reason': 'replay_detected',
                    'frame_id': frame.frame_id}

        # Chain check
        if frame.previous_frame_hash != expected_prev_hash:
            return {'valid': False, 'reason': 'chain_break',
                    'expected': expected_prev_hash[:16] + '...',
                    'got': frame.previous_frame_hash[:16] + '...'}

        # Index monotonicity check
        if frame.frame_index != expected_index:
            return {'valid': False, 'reason': 'index_mismatch',
                    'expected': expected_index, 'got': frame.frame_index}

        # Frame type check
        if frame.frame_type not in VALID_FRAME_TYPES:
            return {'valid': False, 'reason': f'invalid_frame_type:{frame.frame_type}'}

        # Payload hash check (mutating payload after signing breaks this)
        if _canonical_hash(frame.payload) != frame.payload_hash:
            return {'valid': False, 'reason': 'payload_hash_mismatch'}

        # Signature check (suite-aware)
        # _verify_with expects: Ed25519 (pub hex, sig hex), PQ (pub bytes, sig bytes)
        signing_payload_hex = _frame_signing_payload(frame.to_dict())
        try:
            if frame.crypto_suite == 'ed25519':
                sig_ok = _verify_with(
                    frame.crypto_suite,
                    frame.agent_key,
                    bytes.fromhex(signing_payload_hex),
                    frame.signature,
                )
            else:
                sig_ok = _verify_with(
                    frame.crypto_suite,
                    bytes.fromhex(frame.agent_key),
                    bytes.fromhex(signing_payload_hex),
                    bytes.fromhex(frame.signature),
                )
        except Exception as e:
            return {'valid': False, 'reason': f'signature_check_error:{type(e).__name__}'}
        if not sig_ok:
            return {'valid': False, 'reason': 'signature_invalid'}

        # Mark seen
        self._seen_frame_ids.add(frame.frame_id)
        return {'valid': True}


# ─── Self-test ────────────────────────────────────────────────────────

def _self_test() -> int:
    print("acreo_activity_stream self-test")
    print("─" * 50)

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

    # Setup: create an agent
    agent = Identity.create_agent('alice-bot')

    # 1. Round-trip: create stream, append 5 frames, verify all 5
    def round_trip():
        s = ActivityStream(agent)
        s.record_observation({'sensor': 'price', 'value': 67234.50})
        s.record_reasoning({'thought': 'price below threshold'})
        s.record_action({'type': 'order', 'side': 'buy', 'qty': 10})
        s.record_observation({'sensor': 'price', 'value': 67500.00})
        s.record_state({'positions': 10, 'cash': 5000})
        v = StreamVerifier(agent.public_key)
        verdict = v.verify_segment(s.frames)
        return verdict['valid'] and verdict['frames_verified'] == 5
    check("round-trip: 5 frames verify cleanly", round_trip)

    # 2. Hash chain: tampering with frame N invalidates verification at N+1
    def tampered_frame_breaks_chain():
        s = ActivityStream(agent)
        s.record_observation({'a': 1})
        s.record_observation({'a': 2})
        s.record_observation({'a': 3})
        # Tamper with frame 1's payload after the fact
        tampered = ActivityFrame.from_dict(s.frames[1].to_dict())
        tampered.payload = {'a': 999}
        tampered_frames = [s.frames[0], tampered, s.frames[2]]
        v = StreamVerifier(agent.public_key)
        verdict = v.verify_segment(tampered_frames)
        return not verdict['valid']
    check("tampered payload breaks verification", tampered_frame_breaks_chain)

    # 3. Tampered signature rejected
    def tampered_signature_rejected():
        s = ActivityStream(agent)
        s.record_observation({'a': 1})
        tampered = ActivityFrame.from_dict(s.frames[0].to_dict())
        # Flip a hex char in the signature
        sig = tampered.signature
        tampered.signature = ('0' if sig[0] != '0' else '1') + sig[1:]
        v = StreamVerifier(agent.public_key)
        verdict = v.verify_segment([tampered])
        return not verdict['valid'] and 'signature' in verdict.get('reason', '').lower()
    check("tampered signature rejected", tampered_signature_rejected)

    # 4. Insertion: forged frame between two real ones detected
    def insertion_detected():
        s = ActivityStream(agent)
        s.record_observation({'a': 1})
        s.record_observation({'a': 2})
        # Try to insert a forged frame between them
        forged = ActivityFrame(
            frame_id=Entropy.hex(16),
            frame_index=1,  # would push real frame_index 1 to position 2
            frame_type='observation',
            agent_key=agent.public_key,
            timestamp_ms=int(time.time() * 1000),
            previous_frame_hash=_frame_chain_hash(s.frames[0].to_dict()),
            payload_hash=_canonical_hash({'malicious': 'inserted'}),
            payload={'malicious': 'inserted'},
            crypto_suite=agent.crypto_suite,
            protocol=ACTIVITY_PROTOCOL,
            signature='00' * 64,  # not a valid signature
        )
        v = StreamVerifier(agent.public_key)
        verdict = v.verify_segment([s.frames[0], forged, s.frames[1]])
        return not verdict['valid']
    check("insertion attack detected", insertion_detected)

    # 5. Deletion: missing frame in middle breaks chain
    def deletion_detected():
        s = ActivityStream(agent)
        s.record_observation({'a': 1})
        s.record_observation({'a': 2})
        s.record_observation({'a': 3})
        # Skip the middle frame
        v = StreamVerifier(agent.public_key)
        verdict = v.verify_segment([s.frames[0], s.frames[2]])
        return not verdict['valid']
    check("deletion in middle breaks chain", deletion_detected)

    # 6. Out-of-order indices rejected
    def out_of_order_rejected():
        s = ActivityStream(agent)
        s.record_observation({'a': 1})
        s.record_observation({'a': 2})
        v = StreamVerifier(agent.public_key)
        verdict = v.verify_segment([s.frames[1], s.frames[0]])
        return not verdict['valid']
    check("out-of-order frames rejected", out_of_order_rejected)

    # 7. Wrong agent key rejected
    def wrong_agent_rejected():
        s = ActivityStream(agent)
        s.record_observation({'a': 1})
        other_agent = Identity.create_agent('bob-bot')
        v = StreamVerifier(other_agent.public_key)
        verdict = v.verify_segment(s.frames)
        return not verdict['valid'] and verdict.get('reason') == 'wrong_agent_key'
    check("wrong agent key rejected", wrong_agent_rejected)

    # 8. Replay blocked
    def replay_blocked():
        s = ActivityStream(agent)
        s.record_observation({'a': 1})
        v = StreamVerifier(agent.public_key)
        verdict1 = v.verify_segment(s.frames)
        if not verdict1['valid']:
            return False
        # Replay the same frame
        verdict2 = v.verify_segment(s.frames)
        return not verdict2['valid'] and verdict2.get('reason') == 'replay_detected'
    check("replay of same frame blocked", replay_blocked)

    # 9. PQ agent can produce activity stream
    def pq_agent_works():
        pq_agent = Identity.create_agent_pq('alice-pq-bot')
        s = ActivityStream(pq_agent)
        s.record_observation({'a': 1})
        s.record_action({'type': 'pq-action'})
        v = StreamVerifier(pq_agent.public_key)
        verdict = v.verify_segment(s.frames)
        return verdict['valid'] and verdict['frames_verified'] == 2
    check("PQ agent can produce verifiable stream", pq_agent_works)

    # 10. Cross-agent confusion: PQ stream verified against Ed25519 key fails
    def cross_agent_confusion_blocked():
        ed_agent = Identity.create_agent('ed-bot')
        pq_agent = Identity.create_agent_pq('pq-bot')
        s = ActivityStream(pq_agent)
        s.record_observation({'a': 1})
        # Try to verify with the wrong agent's key
        v = StreamVerifier(ed_agent.public_key)
        verdict = v.verify_segment(s.frames)
        return not verdict['valid']
    check("cross-agent confusion blocked", cross_agent_confusion_blocked)

    # 11. Sealed payload pattern: frame contains encrypted payload, chain still verifies
    def sealed_payload_works():
        from acreo_sealed import SealedMessage
        # Recipient who can decrypt
        recipient = Identity.create_user('auditor')
        s = ActivityStream(agent)
        # Seal sensitive content to the recipient
        sensitive = b'private trading strategy details'
        sealed_blob = SealedMessage.seal(recipient.peer_key, sensitive)
        # Frame's payload contains the sealed blob (treated as opaque from
        # the verifier's perspective)
        s.record_observation({'sealed': sealed_blob, 'recipient_hint': 'auditor'})
        # Chain verification works without decrypting
        v = StreamVerifier(agent.public_key)
        verdict = v.verify_segment(s.frames)
        if not verdict['valid']:
            return False
        # Recipient can still recover the content
        recovered = SealedMessage.unseal(
            recipient._peer_priv.hex,
            s.frames[0].payload['sealed']
        )
        return recovered == sensitive
    check("sealed payload: chain verifies, content stays private", sealed_payload_works)

    # 12. Genesis frame: first frame has previous_frame_hash = '0'*64
    def genesis_correct():
        s = ActivityStream(agent)
        s.record_observation({'a': 1})
        return s.frames[0].previous_frame_hash == '0' * 64
    check("genesis frame uses zero hash", genesis_correct)

    print("─" * 50)
    passed = sum(results)
    total = len(results)
    print(f"  {passed}/{total} passed")
    return 0 if passed == total else 1


if __name__ == "__main__":
    import sys
    sys.exit(_self_test())
