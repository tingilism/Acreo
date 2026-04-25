"""
test_proposal.py — Stage A happy path for negotiation protocol
================================================================

Single test: agent creates a ConditionalProof, verifier accepts it.

This is the simplest possible end-to-end check that:
  1. ConditionalProof dataclass works
  2. Identity.propose() produces a valid signed proposal
  3. Verifier.verify_proposal() accepts that valid proposal
  4. No regression in existing primitives

Chaos tests for ConditionalProof (forgery, scope, expiration, etc.) come
in Stage B once settle_pair() exists, because most interesting attacks
require the full negotiation flow to be meaningful.

Run:
    python test_proposal.py
"""

import sys
import time

try:
    from acreo import Acreo, ConditionalProof
except ImportError as e:
    print(f"FATAL: {e}", file=sys.stderr)
    print("Run from Acreo repo root after applying Stage A patches.",
          file=sys.stderr)
    sys.exit(2)


def test(label, condition):
    """Tiny test helper matching acreo.py's style."""
    try:
        ok = condition()
    except Exception as e:
        print(f"  ✗ {label}: raised {type(e).__name__}: {e}")
        return False
    if ok:
        print(f"  ✓ {label}")
        return True
    else:
        print(f"  ✗ {label}: returned falsy")
        return False


def main():
    print("\n  Stage A — ConditionalProof happy path")
    print("  " + "─" * 50)

    a = Acreo()
    user = a.create_user('alice')
    agent = a.create_agent('alice-bot')
    cred = a.delegate(user, agent, ['transact', 'execute'],
                      scope=['polymarket/*'])

    results = []

    # 1. Agent creates a ConditionalProof with an 'always' condition
    proposal = None
    try:
        proposal = a.propose(
            agent, cred,
            action='transact',
            resource='polymarket/btc-100k-2026',
            condition={'type': 'always', 'reason': 'self-binding'},
            valid_until_ms=int(time.time() * 1000) + 60_000,
        )
    except Exception as e:
        print(f"  ✗ propose() raised: {type(e).__name__}: {e}")
        return 1

    results.append(test("propose() returns ConditionalProof",
                        lambda: isinstance(proposal, ConditionalProof)))
    results.append(test("proposal has signature",
                        lambda: bool(proposal.signature)))
    results.append(test("proposal has nonce",
                        lambda: bool(proposal.nonce)))
    results.append(test("proposal action matches",
                        lambda: proposal.action == 'transact'))
    results.append(test("proposal resource matches",
                        lambda: proposal.resource == 'polymarket/btc-100k-2026'))
    results.append(test("proposal condition is 'always'",
                        lambda: proposal.condition['type'] == 'always'))

    # 2. Verifier accepts the standalone proposal
    r = a.verify_proposal(proposal, cred)
    results.append(test("verify_proposal returns valid",
                        lambda: r.get('valid') is True))
    results.append(test("verify_proposal echoes proof_id",
                        lambda: r.get('proof_id') == proposal.proof_id))

    # 3. Counterparty proposal type also works
    cp = None
    try:
        cp = a.propose(
            agent, cred,
            action='execute',
            resource='polymarket/btc-100k-2026',
            condition={'type': 'counterparty_proof',
                       'credential_id': 'placeholder',
                       'proof_id': 'placeholder'},
            valid_until_ms=int(time.time() * 1000) + 60_000,
            paired_with='placeholder-proof-id',
        )
    except Exception as e:
        print(f"  ✗ counterparty propose() raised: {type(e).__name__}: {e}")
        return 1

    r2 = a.verify_proposal(cp, cred)
    results.append(test("counterparty-typed proposal verifies",
                        lambda: r2.get('valid') is True))
    results.append(test("paired_with field preserved",
                        lambda: cp.paired_with == 'placeholder-proof-id'))

    # 4. Existing primitives still work (smoke test for regression)
    ap = a.authorize(agent, cred, 'transact', 'polymarket/btc-100k-2026')
    rv = a.verify_action(ap, cred)
    results.append(test("existing verify_action still works",
                        lambda: rv.get('valid') is True))

    print("  " + "─" * 50)
    passed = sum(results)
    total = len(results)
    print(f"  {passed}/{total} passed")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
