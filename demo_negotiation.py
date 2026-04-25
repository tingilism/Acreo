"""
demo_negotiation.py — Acreo two-party negotiation in action
==============================================================

Walks through two prediction-market bots settling a position swap using
Acreo's negotiation protocol. The story:

  Alice's bot holds a YES position on "BTC > $100k by EOY 2026" on
  Polymarket. Bob's bot wants the position. They agree on a price
  (500 USDC), exchange signed conditional commitments, and atomically
  settle — neither party performs unless both perform.

If you read this file top-to-bottom you should understand the protocol
even without reading acreo.py.

Run:
    python demo_negotiation.py

Requires acreo.py in the same directory with Stage A + Stage B + pair_id
patches applied (run apply_pair_id.py first if not).
"""

import sys
import time

try:
    from acreo import Acreo, ConditionalProof, Entropy
except ImportError as e:
    print(f"FATAL: {e}", file=sys.stderr)
    print("Run from Acreo repo root.", file=sys.stderr)
    sys.exit(2)


# ─── ANSI color codes ─────────────────────────────────────────────────
# Standard escape sequences. Modern PowerShell, macOS Terminal, most Linux
# terminals all render these. If running somewhere they don't, the codes
# are inert and the demo still works — just with extra characters.

class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    GREEN   = "\033[32m"
    YELLOW  = "\033[33m"
    BLUE    = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN    = "\033[36m"
    RED     = "\033[31m"
    GREY    = "\033[90m"


def header(title: str, subtitle: str = ""):
    line = "═" * 63
    print(f"\n{C.BOLD}{C.CYAN}{line}{C.RESET}")
    print(f"  {C.BOLD}{title}{C.RESET}")
    if subtitle:
        print(f"  {C.DIM}{subtitle}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}{line}{C.RESET}")


def section(num: int, title: str):
    print(f"\n{C.BOLD}{C.YELLOW}[{num}] {title}{C.RESET}")
    print(f"{C.DIM}{'─' * 63}{C.RESET}")


def commentary(text: str):
    """Greyed-out explanation of what's happening at the protocol level."""
    for line in text.strip().split("\n"):
        print(f"    {C.GREY}{line}{C.RESET}")


def step(actor: str, action: str, color=C.BLUE):
    """An action being taken by one of the parties."""
    print(f"    {color}{actor}{C.RESET} {action}")


def ok(text: str):
    print(f"    {C.GREEN}✓{C.RESET} {text}")


def reject(text: str):
    print(f"    {C.RED}✗{C.RESET} {text}")


def show_proof(label: str, proof, indent: str = "    "):
    """Pretty-print key fields of a ConditionalProof."""
    print(f"{indent}{C.BOLD}{label}{C.RESET}")
    print(f"{indent}  {C.DIM}proof_id:{C.RESET}    {proof.proof_id}")
    print(f"{indent}  {C.DIM}pair_id:{C.RESET}     {proof.pair_id}")
    print(f"{indent}  {C.DIM}agent_key:{C.RESET}   {proof.agent_key[:16]}...")
    print(f"{indent}  {C.DIM}action:{C.RESET}      {proof.action}")
    print(f"{indent}  {C.DIM}resource:{C.RESET}    {proof.resource}")
    print(f"{indent}  {C.DIM}condition:{C.RESET}   {proof.condition}")
    valid_until_s = (proof.valid_until - int(time.time() * 1000)) / 1000
    print(f"{indent}  {C.DIM}valid for:{C.RESET}   ~{valid_until_s:.0f}s from now")
    print(f"{indent}  {C.DIM}signature:{C.RESET}   {proof.signature[:32]}...")


# ═══════════════════════════════════════════════════════════════════════
# DEMO
# ═══════════════════════════════════════════════════════════════════════

def main():
    header(
        "ACREO NEGOTIATION DEMO",
        "Two prediction-market agents settling a position swap"
    )

    a = Acreo()

    # ─── 1. Setup ─────────────────────────────────────────────────────
    section(1, "SETUP — users delegate to their trading bots")

    alice = a.create_user('alice')
    alice_bot = a.create_agent('alice-bot')
    alice_cred = a.delegate(
        alice, alice_bot, ['transact', 'execute'],
        scope=['polymarket/*']
    )

    bob = a.create_user('bob')
    bob_bot = a.create_agent('bob-bot')
    bob_cred = a.delegate(
        bob, bob_bot, ['transact', 'execute'],
        scope=['polymarket/*']
    )

    step("Alice", "→ creates user identity")
    step("Alice", f"→ delegates to alice-bot {C.DIM}({alice_cred.credential_id[:12]}...){C.RESET}")
    step("  Bob", "→ creates user identity")
    step("  Bob", f"→ delegates to bob-bot   {C.DIM}({bob_cred.credential_id[:12]}...){C.RESET}")

    commentary("""
Each user holds the master key. Each bot has its own keypair and a
scoped credential — it can transact only on polymarket/*. If a bot
is compromised, the user revokes the credential without exposing the
master key.
""")

    # ─── 2. Out-of-band session agreement ────────────────────────────
    section(2, "OUT-OF-BAND PAIR_ID AGREEMENT")

    pair_id = Entropy.hex(16)

    print(f"    Alice's bot {C.GREY}◀────{C.RESET} pair_id: {C.MAGENTA}{pair_id}{C.RESET} {C.GREY}────▶{C.RESET} Bob's bot")

    commentary("""
Before either party commits, they agree on a session identifier.
This happens out of band — over Discord, X DMs, an MCP handshake,
a smart contract event, whatever channel they have. Acreo doesn't
care how — it only cares that both signed proposals reference the
same pair_id.

Neither party has signed anything yet. No commitment exists.
""")

    # ─── 3. Alice's commitment ───────────────────────────────────────
    section(3, "ALICE'S CONDITIONAL COMMITMENT")

    valid_until = int(time.time() * 1000) + 30_000  # 30 second window

    alice_proposal = a.propose(
        alice_bot, alice_cred,
        action='transact',
        resource='polymarket/btc-100k-2026',
        condition={
            'type': 'counterparty_proof',
            'credential_id': bob_cred.credential_id,
            'note': 'transfer YES position to Bob in exchange for 500 USDC',
        },
        valid_until_ms=valid_until,
        pair_id=pair_id,
    )

    step("Alice's bot", f"signs a {C.YELLOW}ConditionalProof{C.RESET}:")
    print()
    show_proof("[Alice → Bob]", alice_proposal, indent="      ")
    print()
    ok("Signed and ready to send to Bob")

    commentary("""
Alice's bot now has a signed commitment, but no obligation yet.
Without a matching proof from Bob's bot referencing the same pair_id,
the commitment dissolves at the valid_until time. Alice can walk
away costlessly until Bob signs.
""")

    # ─── 4. Bob's commitment ─────────────────────────────────────────
    section(4, "BOB'S CONDITIONAL COMMITMENT")

    bob_proposal = a.propose(
        bob_bot, bob_cred,
        action='transact',
        resource='polymarket/btc-100k-2026',
        condition={
            'type': 'counterparty_proof',
            'credential_id': alice_cred.credential_id,
            'note': 'pay 500 USDC to Alice for YES position transfer',
        },
        valid_until_ms=valid_until,
        pair_id=pair_id,
    )

    step("Bob's bot", f"signs a matching {C.YELLOW}ConditionalProof{C.RESET}:")
    print()
    show_proof("[Bob → Alice]", bob_proposal, indent="      ")
    print()
    ok("Signed — both halves of the deal now exist as cryptographic commitments")

    commentary("""
Both parties have committed. Neither has performed yet. The pair
is now eligible for settlement: a verifier sees two matching proofs
with the same pair_id, both signed, both within their time windows,
both referencing each other's credential.
""")

    # ─── 5. Verification (each side checks the other) ───────────────
    section(5, "INDEPENDENT VERIFICATION")

    print(f"    Each party verifies the {C.BOLD}counterparty's{C.RESET} proof before settling.")
    print()

    r_a = a.verify_proposal(alice_proposal)
    r_b = a.verify_proposal(bob_proposal)

    if r_a.get('valid'):
        ok(f"Bob's verification of Alice's proof: {C.GREEN}valid{C.RESET}")
    if r_b.get('valid'):
        ok(f"Alice's verification of Bob's proof: {C.GREEN}valid{C.RESET}")

    commentary("""
verify_proposal checks: signature is correct, credential is valid,
permission is granted, resource is in scope, condition is well-formed,
time window includes now. It's read-only — no nonces consumed yet.
""")

    # ─── 6. Atomic settlement ────────────────────────────────────────
    section(6, "ATOMIC SETTLEMENT")

    print(f"    Either party submits the pair to {C.BOLD}settle_pair{C.RESET}.")
    print(f"    Inside the verifier's critical section:")
    print()
    print(f"      {C.GREY}1. Both proofs verified standalone{C.RESET}")
    print(f"      {C.GREY}2. pair_id equality confirmed{C.RESET}")
    print(f"      {C.GREY}3. Time windows overlap{C.RESET}")
    print(f"      {C.GREY}4. Both nonces consumed atomically{C.RESET}")
    print(f"      {C.GREY}5. Pair recorded as settled{C.RESET}")
    print()

    settlement = a.settle_pair(alice_proposal, bob_proposal, alice_cred, bob_cred)

    if settlement.get('valid'):
        ok(f"{C.BOLD}{C.GREEN}SETTLED{C.RESET}")
        print()
        print(f"      {C.DIM}pair_key:{C.RESET}    {settlement['pair_key'][:48]}...")
        print(f"      {C.DIM}settled_at:{C.RESET}  {settlement['settled_at']} ms")
        print()
        print(f"      {C.BOLD}Party A (Alice):{C.RESET}")
        print(f"        action:    {settlement['party_a']['action']}")
        print(f"        resource:  {settlement['party_a']['resource']}")
        print(f"        proof_id:  {settlement['party_a']['proof_id'][:24]}...")
        print()
        print(f"      {C.BOLD}Party B (Bob):{C.RESET}")
        print(f"        action:    {settlement['party_b']['action']}")
        print(f"        resource:  {settlement['party_b']['resource']}")
        print(f"        proof_id:  {settlement['party_b']['proof_id'][:24]}...")
    else:
        reject(f"Settlement failed: {settlement}")
        return 1

    commentary("""
Both nonces consumed in a single critical section. If anything
inside settle_pair fails, neither nonce is consumed — no half-state
where Alice has 'spent' her commitment but Bob hasn't.

The settlement record is now permanent in the verifier's log. Either
party can present this artifact to prove the trade was agreed.
""")

    # ─── 7. Anti-replay demonstration ────────────────────────────────
    section(7, "ANTI-REPLAY")

    print(f"    What if Alice tries to settle the same pair again?")
    print()

    replay = a.settle_pair(alice_proposal, bob_proposal, alice_cred, bob_cred)
    if not replay.get('valid'):
        reject(f"Replay rejected: {C.RED}{replay.get('reason')}{C.RESET}")
    else:
        print(f"    [unexpected: replay was accepted]")
        return 1

    print()
    print(f"    What if Alice tries to swap the order — settle (B, A)?")
    print()

    replay_swapped = a.settle_pair(bob_proposal, alice_proposal, bob_cred, alice_cred)
    if not replay_swapped.get('valid'):
        reject(f"Swapped-order replay rejected: {C.RED}{replay_swapped.get('reason')}{C.RESET}")
    else:
        print(f"    [unexpected: swapped-order replay was accepted]")
        return 1

    commentary("""
The pair_key is order-independent (sorted hash of both proof_ids), so
settle(A,B) and settle(B,A) detect the same prior settlement. Each
proof's nonce is also consumed — even if the pair_key check were
bypassed somehow, the nonce store catches the second attempt.
""")

    # ─── 8. Tampering demonstration ──────────────────────────────────
    section(8, "TAMPERING ATTEMPT")

    print(f"    What if a third party tries to substitute a different counterparty?")
    print()

    # Build a fresh attacker pair to use as the substitution
    attacker_user = a.create_user('mallory')
    attacker_bot = a.create_agent('mallory-bot')
    attacker_cred = a.delegate(
        attacker_user, attacker_bot, ['transact'],
        scope=['polymarket/*']
    )
    attacker_pair_id = Entropy.hex(16)
    attacker_proposal = a.propose(
        attacker_bot, attacker_cred,
        action='transact',
        resource='polymarket/btc-100k-2026',
        condition={'type': 'counterparty_proof',
                   'credential_id': alice_cred.credential_id},
        valid_until_ms=int(time.time() * 1000) + 30_000,
        pair_id=attacker_pair_id,
    )

    step("Mallory's bot", "tries to pair Alice's old proposal with her own")

    attack_attempt = a.settle_pair(alice_proposal, attacker_proposal, alice_cred)
    if not attack_attempt.get('valid'):
        reject(f"Attack rejected: {C.RED}{attack_attempt.get('reason')}{C.RESET}")
    else:
        print(f"    [unexpected: attack succeeded]")
        return 1

    commentary("""
Alice's pair_id and Mallory's pair_id are different, so the
pair_id_mismatch check catches it. Even if Mallory had used the
same pair_id, Alice's signed condition references Bob's credential
specifically — Mallory's credential wouldn't match.
""")

    # ─── Closing ─────────────────────────────────────────────────────
    print()
    header("DEMO COMPLETE", "Negotiation protocol working end-to-end")
    print(f"\n  {C.GREEN}✓{C.RESET} Two parties negotiated without a trusted intermediary")
    print(f"  {C.GREEN}✓{C.RESET} Both committed conditionally before either performed")
    print(f"  {C.GREEN}✓{C.RESET} Settlement was atomic — both halves or neither")
    print(f"  {C.GREEN}✓{C.RESET} Replay attempts blocked")
    print(f"  {C.GREEN}✓{C.RESET} Substitution attacks blocked")
    print()
    print(f"  See {C.CYAN}chaos_negotiation_v2.py{C.RESET} for the full adversarial test suite.")
    print(f"  See {C.CYAN}acreo-negotiation-protocol-design.md{C.RESET} for the protocol spec.")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
