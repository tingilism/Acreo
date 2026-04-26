"""
fix_settle_pair.py — insert the missing Verifier.settle_pair method
====================================================================

apply_negotiation_stage_b.py reported Patch 3 as SKIP because the find-block
didn't match the actual whitespace in your file. Patches 1, 2, and 4 landed,
but Verifier.settle_pair itself never made it in.

This patcher anchors on a more precise location and inserts the method
between Verifier.accept_heartbeat (which ends at line 487) and
Verifier.verify_proposal (which starts at line 488).

Idempotent — safe to re-run.

Usage:
    python fix_settle_pair.py
"""

import sys
import shutil
from pathlib import Path

ACREO = Path("acreo.py")
MARKER = "def settle_pair(self, proof_a: 'ConditionalProof'"

# Anchor: the last line of accept_heartbeat's body (return statement)
# immediately followed by the start of verify_proposal's def.
FIND = (
    "        return {'valid':True,'kind':'heartbeat','credential_id':proof.credential_id}\n"
    "    def verify_proposal(self, proof: 'ConditionalProof', credential=None) -> Dict:"
)

REPLACE = (
    "        return {'valid':True,'kind':'heartbeat','credential_id':proof.credential_id}\n"
    "\n"
    "    def settle_pair(self, proof_a: 'ConditionalProof', proof_b: 'ConditionalProof',\n"
    "                    cred_a=None, cred_b=None) -> Dict:\n"
    "        \"\"\"Atomically settle two paired ConditionalProofs.\"\"\"\n"
    "        # Standalone verification of each proof first, outside the lock.\n"
    "        ra = self.verify_proposal(proof_a, cred_a)\n"
    "        if not ra.get('valid'):\n"
    "            return {'valid':False,'reason':f'proof_a_invalid:{ra.get(\"reason\")}'}\n"
    "        rb = self.verify_proposal(proof_b, cred_b)\n"
    "        if not rb.get('valid'):\n"
    "            return {'valid':False,'reason':f'proof_b_invalid:{rb.get(\"reason\")}'}\n"
    "\n"
    "        # Pairing structure checks\n"
    "        if proof_a.proof_id == proof_b.proof_id:\n"
    "            return {'valid':False,'reason':'self_pairing_denied'}\n"
    "        if proof_a.agent_key == proof_b.agent_key:\n"
    "            return {'valid':False,'reason':'same_agent_pair_denied'}\n"
    "        if proof_a.paired_with != proof_b.proof_id:\n"
    "            return {'valid':False,'reason':'pairing_mismatch_a_to_b'}\n"
    "        if proof_b.paired_with != proof_a.proof_id:\n"
    "            return {'valid':False,'reason':'pairing_mismatch_b_to_a'}\n"
    "\n"
    "        # Conditions must both be counterparty_proof referencing each other\n"
    "        if proof_a.condition.get('type') != 'counterparty_proof':\n"
    "            return {'valid':False,'reason':'proof_a_condition_not_counterparty'}\n"
    "        if proof_b.condition.get('type') != 'counterparty_proof':\n"
    "            return {'valid':False,'reason':'proof_b_condition_not_counterparty'}\n"
    "        if proof_a.condition.get('credential_id') != proof_b.credential_id:\n"
    "            return {'valid':False,'reason':'proof_a_condition_wrong_credential'}\n"
    "        if proof_a.condition.get('proof_id') != proof_b.proof_id:\n"
    "            return {'valid':False,'reason':'proof_a_condition_wrong_proof_id'}\n"
    "        if proof_b.condition.get('credential_id') != proof_a.credential_id:\n"
    "            return {'valid':False,'reason':'proof_b_condition_wrong_credential'}\n"
    "        if proof_b.condition.get('proof_id') != proof_a.proof_id:\n"
    "            return {'valid':False,'reason':'proof_b_condition_wrong_proof_id'}\n"
    "\n"
    "        # Time window overlap\n"
    "        now = int(time.time() * 1000)\n"
    "        window_start = max(proof_a.valid_after, proof_b.valid_after)\n"
    "        window_end = min(proof_a.valid_until, proof_b.valid_until)\n"
    "        if window_start > window_end:\n"
    "            return {'valid':False,'reason':'window_no_overlap'}\n"
    "        if now < window_start:\n"
    "            return {'valid':False,'reason':f'window_not_yet:{now}<{window_start}'}\n"
    "        if now > window_end:\n"
    "            return {'valid':False,'reason':f'window_expired:{now}>{window_end}'}\n"
    "\n"
    "        pair_key = ':'.join(sorted([proof_a.proof_id, proof_b.proof_id]))\n"
    "        nk_a = f'cp:{proof_a.agent_key}:{proof_a.nonce}'\n"
    "        nk_b = f'cp:{proof_b.agent_key}:{proof_b.nonce}'\n"
    "\n"
    "        # CRITICAL SECTION: nonce check + consume + pair record, all-or-nothing\n"
    "        with self._settle_lock:\n"
    "            if pair_key in self._settled_pairs:\n"
    "                return {'valid':False,'reason':'pair_already_settled'}\n"
    "            if nk_a in self._nonces:\n"
    "                return {'valid':False,'reason':'proof_a_nonce_already_used'}\n"
    "            if nk_b in self._nonces:\n"
    "                return {'valid':False,'reason':'proof_b_nonce_already_used'}\n"
    "            self._nonces[nk_a] = now\n"
    "            self._nonces[nk_b] = now\n"
    "            self._settled_pairs[pair_key] = now\n"
    "\n"
    "        settlement = {'valid':True,'kind':'settlement','pair_key':pair_key,\n"
    "                      'settled_at':now,\n"
    "                      'party_a':{'agent_key':proof_a.agent_key,\n"
    "                                  'credential_id':proof_a.credential_id,\n"
    "                                  'proof_id':proof_a.proof_id,\n"
    "                                  'action':proof_a.action,\n"
    "                                  'resource':proof_a.resource},\n"
    "                      'party_b':{'agent_key':proof_b.agent_key,\n"
    "                                  'credential_id':proof_b.credential_id,\n"
    "                                  'proof_id':proof_b.proof_id,\n"
    "                                  'action':proof_b.action,\n"
    "                                  'resource':proof_b.resource}}\n"
    "        self._log.append(settlement)\n"
    "        return settlement\n"
    "\n"
    "    def verify_proposal(self, proof: 'ConditionalProof', credential=None) -> Dict:"
)


def main():
    if not ACREO.exists():
        print(f"ERROR: {ACREO} not found.")
        sys.exit(2)

    content = ACREO.read_text(encoding="utf-8")

    if MARKER in content:
        print("Already applied — Verifier.settle_pair already exists.")
        return

    if FIND not in content:
        print("SKIP — anchor block didn't match.")
        print("Expected to find this exact text:")
        print("---")
        print(FIND)
        print("---")
        print("Run: Select-String -Path acreo.py -Pattern \"def verify_proposal\" -Context 2,0")
        print("...and paste the output so we can rebuild the anchor.")
        sys.exit(1)

    shutil.copy(ACREO, Path("acreo.py.bak-settle-pair-fix"))
    print("Backup written: acreo.py.bak-settle-pair-fix")

    patched = content.replace(FIND, REPLACE, 1)
    ACREO.write_text(patched, encoding="utf-8")
    print("APPLIED: Verifier.settle_pair inserted")
    print()
    print("Verify with:")
    print("  python acreo.py")
    print("  python chaos_test.py")
    print("  python chaos_heartbeat.py")
    print("  python test_proposal.py")
    print("  python chaos_negotiation.py")


if __name__ == "__main__":
    main()
