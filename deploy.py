"""
deploy.py — Deploy AgentVerifier.sol to Polygon
═════════════════════════════════════════════════
Acreo Protocol

Deploys the on-chain ZK verifier to Polygon mainnet or Amoy testnet.

Setup:
  pip install web3 py-solc-x python-dotenv

  .env file:
    PRIVATE_KEY=your_private_key
    ALCHEMY_RPC=https://polygon-mainnet.g.alchemy.com/v2/YOUR_KEY
    TREASURY=0xYourTreasuryAddress

Run:
  python deploy.py --testnet   → deploy to Amoy testnet
  python deploy.py --mainnet   → deploy to Polygon mainnet
"""

import os, sys, json, time
from pathlib import Path

def check_deps():
    missing = []
    try: from web3 import Web3
    except: missing.append('web3')
    try: import solcx
    except: missing.append('py-solc-x')
    if missing:
        print(f"pip install {' '.join(missing)}")
        sys.exit(1)

check_deps()

from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware
import solcx

try:
    from dotenv import load_dotenv
    load_dotenv()
except: pass

# ── Config ────────────────────────────────────────────────────────────────────

PRIVATE_KEY  = os.getenv("PRIVATE_KEY", "")
MAINNET_RPC  = os.getenv("MAINNET_RPC",
    os.getenv("ALCHEMY_RPC",
        "https://polygon-mainnet.g.alchemy.com/v2/YOUR_ALCHEMY_KEY"))
AMOY_RPC     = os.getenv("AMOY_RPC",
    "https://polygon-amoy.g.alchemy.com/v2/YOUR_AMOY_KEY")
TREASURY     = os.getenv("TREASURY", "0xYourTreasuryAddressHere")
VERIFY_FEE   = Web3.to_wei(os.getenv("VERIFY_FEE_MATIC", "0.001"), 'ether')

SOL_FILE = Path(__file__).parent / "AgentVerifier.sol"


def compile_contract():
    """Compile AgentVerifier.sol."""
    print("Compiling AgentVerifier.sol...")
    try:
        solcx.install_solc('0.8.19')
    except Exception as e:
        print(f"Solc install warning: {e}")

    source = SOL_FILE.read_text()
    # Use standard JSON input to enable viaIR
    import json as _json
    std_input = {
        "language": "Solidity",
        "sources": {"AgentVerifier.sol": {"content": source}},
        "settings": {
            "optimizer": {"enabled": True, "runs": 200},
            "viaIR": True,
            "outputSelection": {
                "*": {"*": ["abi", "evm.bytecode.object"]}
            }
        }
    }
    output = solcx.compile_standard(
        std_input, solc_version="0.8.19"
    )
    contract_out = output["contracts"]["AgentVerifier.sol"]["AgentVerifier"]
    abi      = contract_out["abi"]
    bytecode = contract_out["evm"]["bytecode"]["object"]

    print(f"Compiled — bytecode size: {len(bytecode)//2:,} bytes")
    return abi, bytecode


def deploy(testnet: bool = True):
    """Deploy to Polygon."""
    rpc = AMOY_RPC if testnet else MAINNET_RPC
    net = "Amoy Testnet" if testnet else "Polygon Mainnet"

    print(f"\n  Acreo AgentVerifier Deployment")
    print(f"  {'─'*40}")
    print(f"  Network:  {net}")
    print(f"  Treasury: {TREASURY}")
    print(f"  Fee:      {Web3.from_wei(VERIFY_FEE, 'ether')} MATIC")

    if not PRIVATE_KEY:
        print("\n  ERROR: PRIVATE_KEY not set in .env")
        sys.exit(1)

    if TREASURY == "0xYourTreasuryAddressHere" or not Web3.is_address(TREASURY):
        print("\n  ERROR: TREASURY not set to a valid address in .env")
        sys.exit(1)

    if not testnet:
        confirm = input("\n  About to deploy to MAINNET. Type 'DEPLOY' to confirm: ")
        if confirm.strip() != "DEPLOY":
            print("  Aborted.")
            sys.exit(1)

    w3 = Web3(Web3.HTTPProvider(rpc))
    w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)

    if not w3.is_connected():
        print(f"\n  ERROR: Cannot connect to {rpc}")
        sys.exit(1)

    account = w3.eth.account.from_key(PRIVATE_KEY)
    balance = w3.from_wei(w3.eth.get_balance(account.address), 'ether')

    print(f"  Deployer: {account.address}")
    print(f"  Balance:  {float(balance):.4f} MATIC")
    print(f"  Block:    {w3.eth.block_number:,}")

    if float(balance) < 0.01:
        print("\n  ERROR: Insufficient MATIC for deployment (need ~0.01)")
        sys.exit(1)

    # Compile
    abi, bytecode = compile_contract()

    # Deploy
    print("\n  Deploying...")
    Contract = w3.eth.contract(abi=abi, bytecode=bytecode)

    gas_price = w3.eth.gas_price
    nonce     = w3.eth.get_transaction_count(account.address)

    tx = Contract.constructor(
        Web3.to_checksum_address(TREASURY),
        VERIFY_FEE
    ).build_transaction({
        'from':     account.address,
        'gas':      2_000_000,
        'gasPrice': gas_price,
        'nonce':    nonce,
    })

    signed  = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    print(f"  TX:       {tx_hash.hex()}")
    print("  Waiting for confirmation...")

    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
    address = receipt['contractAddress']
    gas_used = receipt['gasUsed']
    cost = w3.from_wei(gas_used * gas_price, 'ether')

    print(f"\n  ✓ Deployed successfully!")
    print(f"  Contract: {address}")
    print(f"  Gas used: {gas_used:,}")
    print(f"  Cost:     {float(cost):.6f} MATIC")

    # Save deployment info
    deployment = {
        'contract':    'AgentVerifier',
        'address':     address,
        'network':     net,
        'deployer':    account.address,
        'treasury':    TREASURY,
        'verify_fee':  str(VERIFY_FEE),
        'tx_hash':     tx_hash.hex(),
        'block':       receipt['blockNumber'],
        'gas_used':    gas_used,
        'abi':         abi,
        'timestamp':   int(time.time()),
        'version':     '1.0.0',
    }

    out_file = f"deployment_{'testnet' if testnet else 'mainnet'}.json"
    with open(out_file, 'w') as f:
        json.dump(deployment, f, indent=2)

    print(f"  Saved:    {out_file}")
    print(f"\n  Add to .env:")
    print(f"  AGENT_VERIFIER={address}")
    print(f"\n  Polygonscan:")
    explorer = "amoy.polygonscan.com" if testnet else "polygonscan.com"
    print(f"  https://{explorer}/address/{address}")
    print(f"  {'─'*40}\n")

    return address, abi


if __name__ == '__main__':
    testnet = '--mainnet' not in sys.argv
    deploy(testnet=testnet)
