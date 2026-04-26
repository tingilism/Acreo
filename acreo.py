# -*- coding: utf-8 -*-
"""
acreo.py — Acreo Protocol
══════════════════════════
From the Latin arceo — to ward off, protect, keep threats at bay.

Acreo is the identity, privacy and authorization layer for AI agents.
Alien tech to stop data harvesting. Protection that actively repels threats.

Everything in one file:
  - E2EE              ChaCha20-Poly1305 + HKDF-SHA256
  - PII Stripping     Auto-remove emails, phones, SSNs, cards
  - ZKP               Ed25519-Schnorr identity proofs
  - ZK Agent          Credential delegation + action authorization
  - Agent Wallet      Economic identity — agents pay for their own actions
  - Mandate           Enforcement layer — agents cannot act without Acreo
  - Registry          Agents register themselves automatically
  - Beacon            Service discovery — agents find Acreo naturally
  - Verifier API      Hosted toll booth — $0.001 per verification

Run modes:
  python acreo.py              → run all tests
  python acreo.py --proxy      → ambient privacy proxy on :8080
  python acreo.py --api        → verifier API on :8000
  python acreo.py --beacon     → agent discovery beacon on :9000
  python acreo.py --demo       → live demo of full stack
  python acreo.py --registry   → show registry stats

Install:
  pip install cryptography fastapi uvicorn requests
"""

import os, re, json, time, hmac, ctypes, struct, hashlib
import secrets, logging, threading, urllib.parse
from typing import Optional, Dict, List, Any, Tuple, Callable
from dataclasses import dataclass, field, asdict
from functools import wraps
from enum import Enum
from collections import defaultdict

VERSION          = "1.0.0"
PROTOCOL         = "acreo-v1"
PROOF_TTL_MS     = 5 * 60 * 1000
BRAND            = "Acreo"
TAGLINE          = "Ward off threats. Protect what's real."

logging.basicConfig(level=logging.WARNING,
                    format='%(asctime)s [%(levelname)s] %(message)s')
log = logging.getLogger("acreo")

# ═══════════════════════════════════════════════════════════════════
#  DEPENDENCIES
# ═══════════════════════════════════════════════════════════════════

def _check_deps():
    missing = []
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    except ImportError:
        missing.append("cryptography>=42.0.0")
    if missing:
        raise ImportError(f"pip install {' '.join(missing)}")

_check_deps()

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature, InvalidTag

# ═══════════════════════════════════════════════════════════════════
#  CORE CRYPTO
# ═══════════════════════════════════════════════════════════════════

def _zero(data: bytearray):
    try: ctypes.memset((ctypes.c_char * len(data)).from_buffer(data), 0, len(data))
    except:
        for i in range(len(data)): data[i] = 0

class ProtectedKey:
    __slots__ = ('_key',)
    def __init__(self, b): self._key = bytearray(b)
    def __enter__(self): return bytes(self._key)
    def __exit__(self, *_): _zero(self._key)
    def __del__(self): _zero(self._key)
    @property
    def value(self): return bytes(self._key)
    @property
    def hex(self): return self._key.hex()

class Entropy:
    @staticmethod
    def get(n: int) -> bytes:
        s1 = os.urandom(n); s2 = secrets.token_bytes(n)
        s3 = hashlib.sha3_256(struct.pack('>Q', time.time_ns()) +
                               struct.pack('>I', os.getpid())).digest()
        r = bytearray(n)
        for i in range(n): r[i] = s1[i] ^ s2[i] ^ s3[i % len(s3)]
        return bytes(r)
    @staticmethod
    def hex(n=16): return Entropy.get(n).hex()

def _keypair() -> Tuple[str, str]:
    priv = Ed25519PrivateKey.generate(); pub = priv.public_key()
    return (priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                serialization.NoEncryption()).hex(),
            pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex())

def _sign(priv_hex: str, msg: bytes) -> str:
    with ProtectedKey(bytes.fromhex(priv_hex)) as pb:
        return Ed25519PrivateKey.from_private_bytes(pb).sign(msg).hex()

def _verify(pub_hex: str, msg: bytes, sig_hex: str) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(
            bytes.fromhex(sig_hex), msg); return True
    except: return False

def _challenge(data: Dict) -> str:
    return hashlib.sha3_256(
        json.dumps(data, sort_keys=True, separators=(',',':')).encode()
    ).hexdigest()

def _seq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode() if isinstance(a,str) else a,
                                b.encode() if isinstance(b,str) else b)

# ═══════════════════════════════════════════════════════════════════
#  E2EE
# ═══════════════════════════════════════════════════════════════════

class E2EE:
    """ChaCha20-Poly1305 + HKDF-SHA256. Same cipher as Signal."""
    PROTOCOL = b"Acreo_v1"
    def __init__(self, master_key=None):
        self._mk = bytearray(master_key or Entropy.get(32)); self._count = 0
    def __del__(self): _zero(self._mk)
    def _derive(self, uid, n, salt=None):
        info = self.PROTOCOL + uid.encode() + struct.pack('>Q', n)
        return HKDF(algorithm=hashes.SHA256(), length=32,
                    salt=salt or bytes(16), info=info).derive(bytes(self._mk))
    def encrypt(self, uid: str, data: Any) -> str:
        import base64
        pt = json.dumps(data).encode(); n = self._count; self._count += 1
        salt = Entropy.get(16); mk = ProtectedKey(self._derive(uid, n, salt))
        iv = Entropy.get(12); aad = f"{uid}:{n}".encode()
        with mk as k: ct = ChaCha20Poly1305(k).encrypt(iv, pt, aad)
        return base64.b64encode(json.dumps({
            'v': VERSION, 'uid': uid, 'n': base64.b64encode(iv).decode(),
            'c': base64.b64encode(ct).decode(), 's': base64.b64encode(salt).decode(), 'seq': n
        }).encode()).decode()
    def decrypt(self, uid: str, enc: str) -> Any:
        import base64
        p = json.loads(base64.b64decode(enc))
        iv = base64.b64decode(p['n']); ct = base64.b64decode(p['c'])
        salt = base64.b64decode(p['s']); n = p['seq']
        mk = ProtectedKey(self._derive(uid, n, salt)); aad = f"{uid}:{n}".encode()
        try:
            with mk as k: return json.loads(ChaCha20Poly1305(k).decrypt(iv, ct, aad))
        except InvalidTag: raise ValueError("Authentication failed — data tampered")

# ═══════════════════════════════════════════════════════════════════
#  PII STRIPPER
# ═══════════════════════════════════════════════════════════════════

class PIIStripper:
    """Auto-remove PII before data leaves the device.

    Covers common US formats for email, phone, SSN, credit card, IP.
    Patterns are applied in order — cards before SSN so 16-digit card
    numbers are not partially matched as unformatted SSNs.
    Not an exhaustive international PII filter.
    """
    PATTERNS = [
        (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL]'),
        # Credit cards FIRST — strip 13-19 digit card-like sequences before SSN runs
        (r'\b(?:\d{4}[-\s]?){3}\d{4}\b', '[CARD]'),        # 16-digit (Visa/MC/Disc)
        (r'\b3[47]\d{2}[-\s]?\d{6}[-\s]?\d{5}\b', '[CARD]'),  # Amex 15-digit
        # SSN — formatted 123-45-6789 first, then unformatted 9-digit run
        (r'\b\d{3}-\d{2}-\d{4}\b', '[SSN]'),
        (r'(?<!\d)\d{9}(?!\d)', '[SSN]'),                   # 9 digits, not embedded
        (r'\b(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b', '[PHONE]'),
        (r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '[IP]'),
    ]
    def strip(self, text: str) -> Tuple[str, Dict]:
        found = {}
        for pat, rep in self.PATTERNS:
            m = re.findall(pat, text)
            if m:
                found[rep] = found.get(rep, 0) + len(m)
                text = re.sub(pat, rep, text)
        return text, found

# ═══════════════════════════════════════════════════════════════════
#  ZKP
# ═══════════════════════════════════════════════════════════════════

class ZKP:
    """Ed25519-Schnorr ZK identity proofs. Fiat-Shamir, SHA3-256."""
    TTL = PROOF_TTL_MS
    def __init__(self):
        self._nonces: Dict[str,int] = {}  # nonce_key → timestamp_ms
    def _prune_nonces(self):
        """Evict nonces older than TTL — they can never be replayed anyway."""
        cutoff = int(time.time()*1000) - self.TTL
        self._nonces = {k:v for k,v in self._nonces.items() if v > cutoff}
    def keypair(self): return _keypair()
    def prove(self, priv: str, claim: str, ctx: str = PROTOCOL) -> Dict:
        priv_k = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(priv))
        pub    = priv_k.public_key().public_bytes(serialization.Encoding.Raw,
                                                   serialization.PublicFormat.Raw).hex()
        ts = int(time.time()*1000); nc = Entropy.hex(16)
        ch = _challenge({'context':ctx,'claim':claim,'nonce':nc,
                          'publicKey':pub,'timestamp':ts,'version':PROTOCOL})
        sig = _sign(priv, bytes.fromhex(ch))
        return {'claim':claim,'nonce':nc,'context':ctx,'publicKey':pub,
                'challenge':ch,'proof':sig,'timestamp':ts,'version':PROTOCOL,'algorithm':'Ed25519-Schnorr'}
    def verify(self, p: Dict) -> Dict:
        for f in ['claim','nonce','context','publicKey','challenge','proof','timestamp','version']:
            if not p.get(f): return {'valid':False,'reason':f'missing:{f}'}
        age = int(time.time()*1000) - p['timestamp']
        if age > self.TTL: return {'valid':False,'reason':'expired'}
        if age < 0: return {'valid':False,'reason':'future_timestamp'}
        exp = _challenge({'context':p['context'],'claim':p['claim'],'nonce':p['nonce'],
                           'publicKey':p['publicKey'],'timestamp':p['timestamp'],'version':p['version']})
        if not _seq(exp, p['challenge']): return {'valid':False,'reason':'challenge_mismatch'}
        if not _verify(p['publicKey'], bytes.fromhex(p['challenge']), p['proof']):
            return {'valid':False,'reason':'signature_invalid'}
        nk = f"{p['publicKey']}:{p['nonce']}"
        if nk in self._nonces: return {'valid':False,'reason':'replay'}
        self._prune_nonces()
        self._nonces[nk] = int(time.time()*1000)
        return {'valid':True,'claim':p['claim'],'publicKey':p['publicKey']}

# ═══════════════════════════════════════════════════════════════════
#  ZK AGENT
# ═══════════════════════════════════════════════════════════════════

class AcreoError(Exception): pass
class AuthError(AcreoError): pass
class CredentialError(AcreoError): pass
class ExpiredError(AcreoError): pass
class PermissionDenied(AcreoError): pass
class ReplayError(AcreoError): pass
class InsufficientFunds(AcreoError): pass
class MandateViolation(AcreoError): pass
class PIILeakBlocked(AcreoError): pass

class Permission(str, Enum):
    READ='read'; WRITE='write'; EXECUTE='execute'; TRANSACT='transact'
    DELEGATE='delegate'; SPEND='spend'; COMMUNICATE='communicate'
    SEARCH='search'; MEMORY='memory'; ADMIN='admin'
    @classmethod
    def validate(cls, perms):
        bad = [p for p in perms if p not in [e.value for e in cls]]
        if bad: raise ValueError(f"Invalid permissions: {bad}")

@dataclass
class Credential:
    credential_id: str; agent_key: str; user_commitment: str
    permissions: List[str]; scope: List[str]
    issued_at: int; expires_at: int
    max_uses: Optional[int]; spend_limit: Optional[float]
    metadata: Dict; signature: str; protocol: str = PROTOCOL
    heartbeat_interval_ms: Optional[int] = None
    def valid(self) -> bool: return int(time.time()*1000) < self.expires_at
    def has(self, p: str) -> bool: return p in self.permissions
    def in_scope(self, r: str) -> bool:
        if '*' in self.scope: return True
        for s in self.scope:
            if r == s: return True
            if s.endswith('*') and r.startswith(s[:-1]): return True
            if r.startswith(s): return True
        return False
    def to_dict(self): return asdict(self)
    def to_json(self): return json.dumps(self.to_dict(), indent=2)
    @classmethod
    def from_dict(cls, d): return cls(**{k:v for k,v in d.items() if k in cls.__dataclass_fields__})
    @classmethod
    def from_json(cls, s): return cls.from_dict(json.loads(s))

@dataclass
class ActionProof:
    proof_id: str; credential_id: str; agent_key: str
    action: str; resource: str; challenge: str
    signature: str; timestamp: int; nonce: str
    context: Dict; protocol: str = PROTOCOL
    def to_dict(self): return asdict(self)
    def to_json(self): return json.dumps(self.to_dict(), indent=2)
    @classmethod
    def from_dict(cls, d): return cls(**{k:v for k,v in d.items() if k in cls.__dataclass_fields__})

@dataclass
class HeartbeatProof:
    proof_id: str; credential_id: str; agent_key: str
    timestamp: int; nonce: str; challenge: str; signature: str
    protocol: str = PROTOCOL
    def to_dict(self): return asdict(self)
    def to_json(self): return json.dumps(self.to_dict(), indent=2)
    @classmethod
    def from_dict(cls, d): return cls(**{k:v for k,v in d.items() if k in cls.__dataclass_fields__})


@dataclass
class ConditionalProof:
    """Signed conditional commitment from an agent.

    Says: 'I will perform <action> on <resource> if <condition>
    is met between <valid_after> and <valid_until>.'

    Stage A: only standalone verification — no settlement yet.
    Stage B will add settle_pair() to atomically settle two
    matching ConditionalProofs.
    """
    proof_id: str; credential_id: str; agent_key: str
    action: str; resource: str
    condition: Dict          # {type:'counterparty_proof'|'always', ...}
    valid_after: int; valid_until: int
    paired_with: Optional[str]   # legacy field — use pair_id instead
    timestamp: int; nonce: str; challenge: str; signature: str
    protocol: str = PROTOCOL
    pair_id: Optional[str] = None  # shared session id agreed out-of-band
    def to_dict(self): return asdict(self)
    def to_json(self): return json.dumps(self.to_dict(), indent=2)
    @classmethod
    def from_dict(cls, d): return cls(**{k:v for k,v in d.items() if k in cls.__dataclass_fields__})


class Identity:
    """Cryptographic identity — user or AI agent."""
    def __init__(self, priv, pub, kind='agent', label=''):
        self._priv = ProtectedKey(bytes.fromhex(priv) if isinstance(priv, str) else priv)
        self.public_key=pub; self.kind=kind; self.label=label
        self._log: List[Dict]=[]; self._creds: Dict[str,Credential]={}; self._revoked: set=set()
    def __del__(self):
        if hasattr(self, '_priv'): del self._priv
    @classmethod
    def create_user(cls, label='user') -> 'Identity':
        p,q=_keypair(); return cls(p,q,'user',label)
    @classmethod
    def create_agent(cls, label='agent') -> 'Identity':
        p,q=_keypair(); return cls(p,q,'agent',label)
    def delegate(self, agent_key: str, permissions: List[str],
                 scope=None, ttl_hours=24.0, max_uses=None,
                 spend_limit=None, metadata=None,
                 heartbeat_interval_ms: Optional[int] = None) -> Credential:
        if self.kind != 'user': raise CredentialError("Only users can delegate")
        Permission.validate(permissions)
        now=int(time.time()*1000); cid=Entropy.hex(16); salt=Entropy.hex(16)
        commitment = hashlib.sha3_256(
            bytes.fromhex(self.public_key)+bytes.fromhex(salt)).hexdigest()
        payload = {'credential_id':cid,'agent_key':agent_key,'user_commitment':commitment,
                   'permissions':sorted(permissions),'scope':sorted(scope or ['*']),
                   'issued_at':now,'expires_at':now+int(ttl_hours*3600000),
                   'max_uses':max_uses,'spend_limit':spend_limit,'protocol':PROTOCOL,
                   'heartbeat_interval_ms':heartbeat_interval_ms}
        sig = _sign(self._priv.hex, bytes.fromhex(_challenge(payload)))
        meta = metadata or {}
        meta['issuer_pub'] = self.public_key
        return Credential(credential_id=cid,agent_key=agent_key,user_commitment=commitment,
                          permissions=sorted(permissions),scope=sorted(scope or ['*']),
                          issued_at=now,expires_at=now+int(ttl_hours*3600000),
                          max_uses=max_uses,spend_limit=spend_limit,metadata=meta,signature=sig,
                          heartbeat_interval_ms=heartbeat_interval_ms)
    def prove_authorization(self, cred: Credential, action: str,
                             resource='*', context=None) -> ActionProof:
        if self.kind != 'agent': raise AcreoError("Only agents generate proofs")
        if cred.agent_key != self.public_key: raise CredentialError("Credential not for this agent")
        if not cred.valid(): raise ExpiredError("Credential expired")
        if cred.credential_id in self._revoked: raise CredentialError("Credential revoked")
        if not cred.has(action): raise PermissionDenied(f"No permission: {action}")
        now=int(time.time()*1000); nonce=Entropy.hex(16); pid=Entropy.hex(16)
        cd={'proof_id':pid,'credential_id':cred.credential_id,'agent_key':self.public_key,
            'action':action,'resource':resource,'timestamp':now,'nonce':nonce,'protocol':PROTOCOL}
        if context: cd['context_hash']=hashlib.sha3_256(json.dumps(context,sort_keys=True).encode()).hexdigest()
        ch=_challenge(cd); sig=_sign(self._priv.hex,bytes.fromhex(ch))
        self._log.append({'action':action,'resource':resource,'proof_id':pid,'timestamp':now})
        return ActionProof(proof_id=pid,credential_id=cred.credential_id,agent_key=self.public_key,
                           action=action,resource=resource,challenge=ch,signature=sig,
                           timestamp=now,nonce=nonce,context=context or {})
    def prove_heartbeat(self, cred: Credential) -> HeartbeatProof:
        """Agent produces a signed heartbeat proving it's alive and uncompromised."""
        if self.kind != 'agent': raise AcreoError("Only agents produce heartbeats")
        if cred.agent_key != self.public_key: raise CredentialError("Credential not for this agent")
        if not cred.valid(): raise ExpiredError("Credential expired")
        if cred.credential_id in self._revoked: raise CredentialError("Credential revoked")
        now=int(time.time()*1000); nonce=Entropy.hex(16); pid=Entropy.hex(16)
        cd={'proof_id':pid,'credential_id':cred.credential_id,'agent_key':self.public_key,
            'timestamp':now,'nonce':nonce,'protocol':PROTOCOL,'kind':'heartbeat'}
        ch=_challenge(cd); sig=_sign(self._priv.hex,bytes.fromhex(ch))
        self._log.append({'action':'heartbeat','proof_id':pid,'timestamp':now})
        return HeartbeatProof(proof_id=pid,credential_id=cred.credential_id,
                               agent_key=self.public_key,timestamp=now,nonce=nonce,
                               challenge=ch,signature=sig)

    def propose(self, cred: Credential, action: str, resource: str,
                condition: Dict, valid_until_ms: int,
                pair_id: Optional[str] = None,
                paired_with: Optional[str] = None,
                valid_after_ms: Optional[int] = None) -> ConditionalProof:
        """Agent creates a signed conditional commitment.

        condition is a dict with at least a 'type' field.
        Stage A supports: 'always', 'counterparty_proof'.
        valid_until_ms is the unix-ms timestamp the commitment expires.
        """
        if self.kind != 'agent':
            raise AcreoError("Only agents create proposals")
        if cred.agent_key != self.public_key:
            raise CredentialError("Credential not for this agent")
        if not cred.valid():
            raise ExpiredError("Credential expired")
        if cred.credential_id in self._revoked:
            raise CredentialError("Credential revoked")
        if not cred.has(action):
            raise PermissionDenied(f"No permission: {action}")
        if resource != '*' and not cred.in_scope(resource):
            raise CredentialError(f"Resource out of scope: {resource}")
        if not isinstance(condition, dict) or 'type' not in condition:
            raise ValueError("condition must be a dict with a 'type' field")
        if condition['type'] not in ('always', 'counterparty_proof'):
            raise ValueError(f"Unknown condition type: {condition['type']}")
        now = int(time.time() * 1000)
        if valid_until_ms <= now:
            raise ValueError(f"valid_until_ms in the past: {valid_until_ms} <= {now}")
        valid_after = valid_after_ms if valid_after_ms is not None else now
        nonce = Entropy.hex(16); pid = Entropy.hex(16)
        cd = {'proof_id':pid,'credential_id':cred.credential_id,
              'agent_key':self.public_key,'action':action,'resource':resource,
              'condition':condition,'valid_after':valid_after,
              'valid_until':valid_until_ms,'paired_with':paired_with,
              'pair_id':pair_id,
              'timestamp':now,'nonce':nonce,'protocol':PROTOCOL,
              'kind':'conditional_proof'}
        ch = _challenge(cd); sig = _sign(self._priv.hex, bytes.fromhex(ch))
        self._log.append({'kind':'propose','action':action,'resource':resource,
                           'proof_id':pid,'timestamp':now})
        return ConditionalProof(
            proof_id=pid, credential_id=cred.credential_id,
            agent_key=self.public_key, action=action, resource=resource,
            condition=condition, valid_after=valid_after,
            valid_until=valid_until_ms, paired_with=paired_with,
            pair_id=pair_id,
            timestamp=now, nonce=nonce, challenge=ch, signature=sig)

    def _x25519_keypair(self):
        """Derive X25519 keypair from this identity's Ed25519 seed.

        Lazy + cached. Uses the standard Ed25519→X25519 conversion that
        libsodium implements as crypto_sign_ed25519_sk_to_curve25519.
        Both keys live alongside each other; neither key compromises
        the other within Curve25519's security model.
        """
        if self.kind not in ('user', 'agent'):
            raise AcreoError("only user/agent identities have private keys")
        if not hasattr(self, '_x25519_cache'):
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
            from cryptography.hazmat.primitives import serialization
            import hashlib
            # Take the Ed25519 32-byte seed, hash it with SHA-512, take the
            # first 32 bytes, clamp to a valid X25519 scalar. Standard pattern.
            seed = bytes.fromhex(self._priv.hex)
            h = hashlib.sha512(seed).digest()
            scalar = bytearray(h[:32])
            scalar[0] &= 248
            scalar[31] &= 127
            scalar[31] |= 64
            x_priv = X25519PrivateKey.from_private_bytes(bytes(scalar))
            x_priv_hex = x_priv.private_bytes(
                serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                serialization.NoEncryption()).hex()
            x_pub_hex = x_priv.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
            self._x25519_cache = (x_priv_hex, x_pub_hex)
        return self._x25519_cache

    @property
    def peer_key(self) -> str:
        """X25519 public key for sealed-message addressing (hex)."""
        _, pub = self._x25519_keypair()
        return pub

    def send(self, peer_key_hex: str, payload: bytes) -> str:
        """Encrypt payload to a peer's X25519 public key.

        Returns a base64-encoded sealed blob. Only the holder of the matching
        X25519 private key can decrypt. Sender is NOT authenticated by default
        — sign the payload first if you need authenticated sealed messages.
        """
        if self.kind not in ('user', 'agent'):
            raise AcreoError("only user/agent identities can send sealed messages")
        from acreo_sealed import SealedMessage
        if not isinstance(payload, (bytes, bytearray)):
            raise TypeError(f"payload must be bytes, got {type(payload).__name__}")
        return SealedMessage.seal(peer_key_hex, bytes(payload))

    def receive(self, sealed_blob: str) -> bytes:
        """Decrypt a sealed message addressed to this identity."""
        if self.kind not in ('user', 'agent'):
            raise AcreoError("only user/agent identities can receive sealed messages")
        from acreo_sealed import SealedMessage
        priv, _ = self._x25519_keypair()
        return SealedMessage.unseal(priv, sealed_blob)

    def store(self, cred): self._creds[cred.credential_id]=cred
    def get_valid_credentials(self): return [c for c in self._creds.values() if c.valid()]
    def revoke(self, cid): self._revoked.add(cid)
    def audit(self): return self._log

class Verifier:
    """Verifies agent proofs. Learns what. Never who."""
    def __init__(self, ttl=PROOF_TTL_MS):
        self._creds: Dict[str,Credential]={}; self._nonces: Dict[str,int]={}
        self._log: List[Dict]=[]; self._ttl=ttl
        self._last_heartbeat: Dict[str,int]={}
        self._settle_lock = threading.Lock()
        self._settled_pairs: Dict[str,int]={}  # pair_key → ms timestamp
    def register_credential(self, cred):
        self._creds[cred.credential_id]=cred
        if cred.heartbeat_interval_ms is not None:
            self._last_heartbeat[cred.credential_id] = cred.issued_at
    def accept_heartbeat(self, proof, credential=None) -> Dict:
        """Process a signed heartbeat. Resets the liveness timer if valid."""
        if proof is None:
            return {'valid':False,'reason':'heartbeat_proof_is_none'}
        now=int(time.time()*1000); age=now-proof.timestamp
        if age > self._ttl: return {'valid':False,'reason':f'heartbeat_expired:{age}ms'}
        if proof.timestamp > now+60000: return {'valid':False,'reason':'heartbeat_future_timestamp'}
        nk=f"hb:{proof.agent_key}:{proof.nonce}"
        if nk in self._nonces: return {'valid':False,'reason':'heartbeat_replay_detected'}
        c=credential or self._creds.get(proof.credential_id)
        if not c: return {'valid':False,'reason':'heartbeat_credential_not_found'}
        if not c.valid(): return {'valid':False,'reason':'heartbeat_credential_expired'}
        if not _seq(proof.agent_key,c.agent_key):
            return {'valid':False,'reason':'heartbeat_agent_key_mismatch'}
        cd={'proof_id':proof.proof_id,'credential_id':proof.credential_id,
            'agent_key':proof.agent_key,'timestamp':proof.timestamp,'nonce':proof.nonce,
            'protocol':proof.protocol,'kind':'heartbeat'}
        if not _seq(_challenge(cd),proof.challenge):
            return {'valid':False,'reason':'heartbeat_challenge_mismatch'}
        if not _verify(proof.agent_key,bytes.fromhex(proof.challenge),proof.signature):
            return {'valid':False,'reason':'heartbeat_signature_invalid'}
        self._nonces[nk]=now
        self._last_heartbeat[proof.credential_id]=now
        self._log.append({'valid':True,'kind':'heartbeat','credential_id':proof.credential_id,
                           'agent_key':proof.agent_key,'timestamp':now})
        return {'valid':True,'kind':'heartbeat','credential_id':proof.credential_id}

    def settle_pair(self, proof_a: 'ConditionalProof', proof_b: 'ConditionalProof',
                    cred_a=None, cred_b=None) -> Dict:
        """Atomically settle two paired ConditionalProofs."""
        # Standalone verification of each proof first, outside the lock.
        ra = self.verify_proposal(proof_a, cred_a)
        if not ra.get('valid'):
            return {'valid':False,'reason':f'proof_a_invalid:{ra.get("reason")}'}
        rb = self.verify_proposal(proof_b, cred_b)
        if not rb.get('valid'):
            return {'valid':False,'reason':f'proof_b_invalid:{rb.get("reason")}'}

        # Pairing structure checks
        if proof_a.proof_id == proof_b.proof_id:
            return {'valid':False,'reason':'self_pairing_denied'}
        if proof_a.agent_key == proof_b.agent_key:
            return {'valid':False,'reason':'same_agent_pair_denied'}
        if proof_a.pair_id is None or proof_b.pair_id is None:
            return {'valid':False,'reason':'missing_pair_id'}
        if proof_a.pair_id != proof_b.pair_id:
            return {'valid':False,'reason':'pair_id_mismatch'}

        # Conditions must both be counterparty_proof referencing each other's credential
        if proof_a.condition.get('type') != 'counterparty_proof':
            return {'valid':False,'reason':'proof_a_condition_not_counterparty'}
        if proof_b.condition.get('type') != 'counterparty_proof':
            return {'valid':False,'reason':'proof_b_condition_not_counterparty'}
        if proof_a.condition.get('credential_id') != proof_b.credential_id:
            return {'valid':False,'reason':'proof_a_condition_wrong_credential'}
        if proof_b.condition.get('credential_id') != proof_a.credential_id:
            return {'valid':False,'reason':'proof_b_condition_wrong_credential'}

        # Time window overlap
        now = int(time.time() * 1000)
        window_start = max(proof_a.valid_after, proof_b.valid_after)
        window_end = min(proof_a.valid_until, proof_b.valid_until)
        if window_start > window_end:
            return {'valid':False,'reason':'window_no_overlap'}
        if now < window_start:
            return {'valid':False,'reason':f'window_not_yet:{now}<{window_start}'}
        if now > window_end:
            return {'valid':False,'reason':f'window_expired:{now}>{window_end}'}

        pair_key = ':'.join(sorted([proof_a.proof_id, proof_b.proof_id]))
        nk_a = f'cp:{proof_a.agent_key}:{proof_a.nonce}'
        nk_b = f'cp:{proof_b.agent_key}:{proof_b.nonce}'

        # CRITICAL SECTION: nonce check + consume + pair record, all-or-nothing
        with self._settle_lock:
            if pair_key in self._settled_pairs:
                return {'valid':False,'reason':'pair_already_settled'}
            if nk_a in self._nonces:
                return {'valid':False,'reason':'proof_a_nonce_already_used'}
            if nk_b in self._nonces:
                return {'valid':False,'reason':'proof_b_nonce_already_used'}
            self._nonces[nk_a] = now
            self._nonces[nk_b] = now
            self._settled_pairs[pair_key] = now

        settlement = {'valid':True,'kind':'settlement','pair_key':pair_key,
                      'settled_at':now,
                      'party_a':{'agent_key':proof_a.agent_key,
                                  'credential_id':proof_a.credential_id,
                                  'proof_id':proof_a.proof_id,
                                  'action':proof_a.action,
                                  'resource':proof_a.resource},
                      'party_b':{'agent_key':proof_b.agent_key,
                                  'credential_id':proof_b.credential_id,
                                  'proof_id':proof_b.proof_id,
                                  'action':proof_b.action,
                                  'resource':proof_b.resource}}
        self._log.append(settlement)
        return settlement

    def verify_proposal(self, proof: 'ConditionalProof', credential=None) -> Dict:
        """Verify a ConditionalProof as a standalone signed commitment.

        Stage A: checks signature, expiration, scope, permission, condition shape.
        Does NOT consume nonce — that happens at settlement (Stage B).
        Does NOT check whether the condition is currently met — verifying that
        the proposal is well-formed is a separate question from whether it binds.
        """
        def fail(r):
            self._log.append({'valid':False,'kind':'proposal','reason':r,
                               'timestamp':int(time.time()*1000)})
            return {'valid':False,'reason':r}
        if proof is None:
            return {'valid':False,'reason':'proposal_proof_is_none'}
        now = int(time.time() * 1000)
        if now >= proof.valid_until:
            return fail(f'proposal_expired:{now}>={proof.valid_until}')
        if proof.timestamp > now + 60000:
            return fail('proposal_future_timestamp')
        if proof.valid_after > proof.valid_until:
            return fail('proposal_invalid_window')
        c = credential or self._creds.get(proof.credential_id)
        if not c:
            return fail('proposal_credential_not_found')
        if not c.valid():
            return fail('proposal_credential_expired')
        if not _seq(proof.agent_key, c.agent_key):
            return fail('proposal_agent_key_mismatch')
        # Verify the credential's own signature (same logic as verify())
        issuer_pub = c.metadata.get('issuer_pub') if c.metadata else None
        if not issuer_pub:
            return fail('proposal_credential_missing_issuer_pub')
        cred_payload = {'credential_id':c.credential_id,'agent_key':c.agent_key,
                        'user_commitment':c.user_commitment,
                        'permissions':sorted(c.permissions),'scope':sorted(c.scope),
                        'issued_at':c.issued_at,'expires_at':c.expires_at,
                        'max_uses':c.max_uses,'spend_limit':c.spend_limit,
                        'protocol':PROTOCOL,
                        'heartbeat_interval_ms':c.heartbeat_interval_ms}
        if not _verify(issuer_pub, bytes.fromhex(_challenge(cred_payload)), c.signature):
            return fail('proposal_credential_signature_invalid')
        # Permission and scope checks
        if not c.has(proof.action):
            return fail(f'proposal_permission_denied:{proof.action}')
        if proof.resource != '*' and not c.in_scope(proof.resource):
            return fail('proposal_out_of_scope')
        # Condition shape
        if not isinstance(proof.condition, dict) or 'type' not in proof.condition:
            return fail('proposal_malformed_condition')
        if proof.condition['type'] not in ('always', 'counterparty_proof'):
            return fail(f'proposal_unknown_condition_type:{proof.condition["type"]}')
        # Re-derive challenge and verify signature on the proposal itself
        cd = {'proof_id':proof.proof_id,'credential_id':proof.credential_id,
              'agent_key':proof.agent_key,'action':proof.action,
              'resource':proof.resource,'condition':proof.condition,
              'valid_after':proof.valid_after,'valid_until':proof.valid_until,
              'paired_with':proof.paired_with,
              'pair_id':proof.pair_id,
              'timestamp':proof.timestamp,
              'nonce':proof.nonce,'protocol':proof.protocol,
              'kind':'conditional_proof'}
        if not _seq(_challenge(cd), proof.challenge):
            return fail('proposal_challenge_mismatch')
        if not _verify(proof.agent_key, bytes.fromhex(proof.challenge), proof.signature):
            return fail('proposal_signature_invalid')
        result = {'valid':True,'kind':'proposal','proof_id':proof.proof_id,
                  'credential_id':proof.credential_id,'agent_key':proof.agent_key,
                  'action':proof.action,'resource':proof.resource,
                  'condition':proof.condition,'paired_with':proof.paired_with,
                  'valid_until':proof.valid_until}
        self._log.append(result)
        return result

    def verify(self, proof: ActionProof, credential=None) -> Dict:
        if proof is None:
            return {'valid':False,'reason':'proof_is_none'}
        def fail(r):
            self._log.append({'valid':False,'reason':r,'action':getattr(proof,'action','?'),
                               'timestamp':int(time.time()*1000)})
            return {'valid':False,'reason':r}
        now=int(time.time()*1000); age=now-proof.timestamp
        if age > self._ttl: return fail(f'expired:{age}ms')
        if proof.timestamp > now+60000: return fail('future_timestamp')
        nk=f"{proof.agent_key}:{proof.nonce}"
        if nk in self._nonces: return fail('replay_attack_detected')
        # Prune stale nonces — anything older than TTL can never be replayed anyway
        cutoff = now - self._ttl
        self._nonces = {k:v for k,v in self._nonces.items() if v > cutoff}
        c=credential or self._creds.get(proof.credential_id)
        if not c: return fail('credential_not_found')
        if not c.valid(): return fail('credential_expired')
        if not _seq(proof.agent_key,c.agent_key): return fail('agent_key_mismatch')
        # Verify credential signature — prevents TTL extension and permission injection
        issuer_pub = c.metadata.get('issuer_pub') if c.metadata else None
        if not issuer_pub:
            return fail('credential_missing_issuer_pub')
        cred_payload = {'credential_id':c.credential_id,'agent_key':c.agent_key,
                        'user_commitment':c.user_commitment,
                        'permissions':sorted(c.permissions),'scope':sorted(c.scope),
                        'issued_at':c.issued_at,'expires_at':c.expires_at,
                        'max_uses':c.max_uses,'spend_limit':c.spend_limit,'protocol':PROTOCOL,
                        'heartbeat_interval_ms':c.heartbeat_interval_ms}
        cred_challenge = _challenge(cred_payload)
        if not _verify(issuer_pub, bytes.fromhex(cred_challenge), c.signature):
            return fail('credential_signature_invalid')
        if c.heartbeat_interval_ms is not None:
            last_hb = self._last_heartbeat.get(c.credential_id, c.issued_at)
            if now - last_hb > c.heartbeat_interval_ms:
                return fail(f'heartbeat_overdue:{now - last_hb}ms>{c.heartbeat_interval_ms}ms')
        if not c.has(proof.action): return fail(f'permission_denied:{proof.action}')
        if proof.resource!='*' and not c.in_scope(proof.resource): return fail(f'out_of_scope')
        cd={'proof_id':proof.proof_id,'credential_id':proof.credential_id,'agent_key':proof.agent_key,
            'action':proof.action,'resource':proof.resource,'timestamp':proof.timestamp,
            'nonce':proof.nonce,'protocol':proof.protocol}
        if proof.context: cd['context_hash']=hashlib.sha3_256(json.dumps(proof.context,sort_keys=True).encode()).hexdigest()
        if not _seq(_challenge(cd),proof.challenge): return fail('challenge_mismatch')
        if not _verify(proof.agent_key,bytes.fromhex(proof.challenge),proof.signature):
            return fail('signature_invalid')
        self._nonces[nk]=now
        result={'valid':True,'action':proof.action,'resource':proof.resource,
                'agent_key':proof.agent_key,'proof_id':proof.proof_id,'timestamp':proof.timestamp}
        self._log.append(result); return result
    def audit(self): return self._log
    def summary(self):
        t=len(self._log); v=sum(1 for e in self._log if e.get('valid'))
        return {'total':t,'verified':v,'denied':t-v}

# ═══════════════════════════════════════════════════════════════════
#  AGENT WALLET
# ═══════════════════════════════════════════════════════════════════

PRICING = {'read':0.0001,'write':0.001,'execute':0.005,'transact':0.010,
           'verify':0.001,'default':0.001}

@dataclass
class Transaction:
    tx_id: str; wallet_id: str; tx_type: str; amount_usd: float
    balance_before: float; balance_after: float
    action: str; resource: str; timestamp: int; status: str
    signature: str; metadata: Dict = field(default_factory=dict)
    def to_dict(self): return asdict(self)

@dataclass
class PaymentReceipt:
    approved: bool; tx_id: str; amount_usd: float
    balance: float; action: str; reason: Optional[str] = None
    @property
    def denied(self): return not self.approved

class AgentWallet:
    """Economic identity. Agents pay for their own actions."""
    def __init__(self, wallet_id, private_key, public_key, label,
                 budget_usd, spend_limit_per_tx=None, spend_limit_per_day=None):
        self.wallet_id=wallet_id
        self._priv=ProtectedKey(bytes.fromhex(private_key) if isinstance(private_key,str) else private_key)
        self.public_key=public_key
        self.label=label; self._balance=budget_usd; self.initial_budget=budget_usd
        self.spend_limit_per_tx=spend_limit_per_tx or budget_usd
        self.spend_limit_per_day=spend_limit_per_day or budget_usd
        self._txs: List[Transaction]=[]; self._day_spend=0.0
        self._day_reset=int(time.time())+86400
        self._record('fund',budget_usd,'fund','wallet','complete')
    @classmethod
    def create(cls, label='agent', budget_usd=10.0,
               spend_limit_per_tx=None, spend_limit_per_day=None):
        p,q=_keypair()
        return cls(Entropy.hex(16),p,q,label,budget_usd,spend_limit_per_tx,spend_limit_per_day)
    def pay_for_action(self, action, resource='*', amount_usd=None):
        return self._charge(amount_usd or PRICING.get(action,PRICING['default']),'action_fee',action,resource)
    def fund(self, amount):
        self._balance+=amount; self._record('fund',amount,'fund','wallet','complete')
        return PaymentReceipt(True,Entropy.hex(8),amount,self._balance,'fund')
    def _charge(self, amount, tx_type, action, resource):
        if amount<=0:
            tx=self._record(tx_type,amount,action,resource,'declined',{'reason':'invalid_amount'})
            return PaymentReceipt(False,tx.tx_id,amount,self._balance,action,'invalid_amount')
        if time.time()>self._day_reset: self._day_spend=0.0; self._day_reset=int(time.time())+86400
        if amount>self._balance:
            tx=self._record(tx_type,amount,action,resource,'declined',{'reason':'insufficient_balance'})
            return PaymentReceipt(False,tx.tx_id,amount,self._balance,action,'insufficient_balance')
        if amount>self.spend_limit_per_tx:
            tx=self._record(tx_type,amount,action,resource,'declined',{'reason':'per_tx_limit_exceeded'})
            return PaymentReceipt(False,tx.tx_id,amount,self._balance,action,'per_tx_limit_exceeded')
        if self._day_spend+amount>self.spend_limit_per_day:
            tx=self._record(tx_type,amount,action,resource,'declined',{'reason':'daily_limit_exceeded'})
            return PaymentReceipt(False,tx.tx_id,amount,self._balance,action,'daily_limit_exceeded')
        self._balance-=amount; self._day_spend+=amount
        tx=self._record(tx_type,amount,action,resource,'approved')
        return PaymentReceipt(True,tx.tx_id,round(amount,8),self._balance,action)
    def _record(self, tx_type, amount, action, resource, status, metadata=None):
        tx_id=Entropy.hex(8); bal_before=self._balance if tx_type!='fund' else self._balance-amount
        sign_data=json.dumps({'tx_id':tx_id,'wallet_id':self.wallet_id,'tx_type':tx_type,
                               'amount':round(amount,8),'action':action,'timestamp':int(time.time()*1000),
                               'status':status},sort_keys=True).encode()
        sig=_sign(self._priv.hex,hashlib.sha3_256(sign_data).digest())
        tx=Transaction(tx_id=tx_id,wallet_id=self.wallet_id,tx_type=tx_type,
                       amount_usd=round(amount,8),balance_before=round(bal_before,8),
                       balance_after=round(self._balance,8),action=action,resource=resource,
                       timestamp=int(time.time()*1000),status=status,signature=sig,metadata=metadata or {})
        self._txs.append(tx); return tx
    @property
    def balance_usd(self): return round(self._balance,6)
    @property
    def is_funded(self): return self._balance > 0
    def summary(self):
        return {'wallet_id':self.wallet_id,'label':self.label,'balance_usd':self.balance_usd,
                'initial_budget':self.initial_budget,'spent_usd':round(self.initial_budget-self._balance,6),
                'tx_total':len(self._txs),'is_funded':self.is_funded}

# ═══════════════════════════════════════════════════════════════════
#  MANDATE
# ═══════════════════════════════════════════════════════════════════

@dataclass
class MandateConfig:
    require_wallet: bool=True; require_payment: bool=True
    strip_pii: bool=True; block_pii: bool=False
    audit_all: bool=True; min_balance: float=0.001

class MandatedAgent:
    """Base class for all Acreo-mandated agents. Cannot act without Acreo."""
    def __init__(self, agent_id, label, wallet, config=None):
        self.agent_id=agent_id; self.label=label; self.wallet=wallet
        self._config=config or MandateConfig(); self._pii=PIIStripper()
        self._log: List[Dict]=[]
    @classmethod
    def create(cls, label='agent', budget_usd=10.0,
               spend_limit_per_tx=None, config=None):
        wallet=AgentWallet.create(label=label,budget_usd=budget_usd,
                                   spend_limit_per_tx=spend_limit_per_tx)
        return cls(Entropy.hex(16),label,wallet,config)
    def act(self, action, resource='*', data=None, **kwargs) -> Dict:
        if not action or not isinstance(action, str):
            raise ValueError(f"action must be a non-empty string, got {action!r}")
        result={'allowed':False,'paid':False,'pii_found':{},'clean_data':data,'tx_id':None,'reason':None}
        if self._config.require_wallet:
            if not self.wallet or not self.wallet.is_funded:
                raise InsufficientFunds(f"'{self.label}' wallet empty — fund with wallet.fund(amount)")
            if self.wallet.balance_usd < self._config.min_balance:
                raise InsufficientFunds(f"'{self.label}' balance below minimum")
        if data and self._config.strip_pii:
            clean,found=self._pii.strip(data)
            result['pii_found']=found; result['clean_data']=clean
            if found and self._config.block_pii:
                raise PIILeakBlocked(f"PII detected: {list(found.keys())}")
        if self._config.require_payment and self.wallet:
            receipt=self.wallet.pay_for_action(action,resource)
            if receipt.denied:
                raise InsufficientFunds(f"Payment declined: {receipt.reason}")
            result['paid']=True; result['tx_id']=receipt.tx_id
        result['allowed']=True
        self._log.append({'action':action,'resource':resource,'timestamp':int(time.time()*1000),
                           'allowed':True,'tx_id':result['tx_id']})
        return result
    def protect(self, text):
        clean,found=self._pii.strip(text)
        return {'protected':clean,'pii_found':found,'clean':len(found)==0}
    @property
    def balance(self): return self.wallet.balance_usd if self.wallet else 0.0
    @property
    def is_ready(self): return self.wallet is not None and self.wallet.is_funded
    def fund(self, amount): return self.wallet.fund(amount) if self.wallet else None
    def audit(self):
        return {'agent_id':self.agent_id,'label':self.label,'balance':self.balance,
                'actions':self._log,'wallet':self.wallet.summary() if self.wallet else None}

def mandated(action: str, resource: str = "*"):
    """Decorator. Wraps any method with Acreo mandate enforcement."""
    def decorator(fn):
        @wraps(fn)
        def wrapper(self, *args, **kwargs):
            if not isinstance(self, MandatedAgent):
                raise MandateViolation("@mandated requires MandatedAgent base class")
            self.act(action, resource)
            return fn(self, *args, **kwargs)
        return wrapper
    return decorator

# ═══════════════════════════════════════════════════════════════════
#  REGISTRY
# ═══════════════════════════════════════════════════════════════════

@dataclass
class AgentRecord:
    agent_id: str; public_key: str; label: str; framework: str
    permissions: List[str]; registered_at: int; last_seen: int
    credential_id: Optional[str]; credential_expires: Optional[int]
    action_count: int=0; status: str="active"; metadata: Dict=field(default_factory=dict)
    def is_credentialed(self):
        return (self.credential_id is not None and
                self.credential_expires is not None and
                int(time.time()*1000) < self.credential_expires)
    def to_dict(self):
        return {**asdict(self), 'public_key': self.public_key[:16]+'...',
                'credentialed': self.is_credentialed()}

class AgentRegistry:
    """Agents register themselves. Acreo issues credentials automatically."""
    def __init__(self):
        self._agents: Dict[str,AgentRecord]={}; self._nonces: set=set()
        self._issuer=Identity.create_user("acreo-registry")
        self._verifier=Verifier()
    def register(self, public_key, label, framework, permissions,
                 challenge, signature, timestamp, nonce, metadata=None) -> Dict:
        if len(public_key) != 64: return {'success':False,'reason':'invalid_public_key'}
        age_ms=int(time.time()*1000)-timestamp
        if age_ms > PROOF_TTL_MS: return {'success':False,'reason':'request_expired'}
        nk=f"{public_key}:{nonce}"
        if nk in self._nonces: return {'success':False,'reason':'replay_detected'}
        exp=_challenge({'public_key':public_key,'label':label,'nonce':nonce,
                         'timestamp':timestamp,'purpose':'acreo_registration','version':VERSION})
        if not _seq(exp,challenge): return {'success':False,'reason':'challenge_mismatch'}
        if not _verify(public_key,bytes.fromhex(challenge),signature):
            return {'success':False,'reason':'proof_of_ownership_failed'}
        # Default to read-only. Higher-privilege permissions (write, execute,
        # transact, spend, delegate, admin) require explicit user delegation
        # via Identity.delegate() — the registry will not auto-grant them.
        PRIVILEGED = {'write','execute','transact','spend','delegate','admin'}
        requested  = permissions or ['read']
        perms=[p for p in requested
               if p in [e.value for e in Permission] and p not in PRIVILEGED]
        if not perms:
            perms = ['read']
        denied_privileged = [p for p in requested if p in PRIVILEGED]
        cred=self._issuer.delegate(public_key,perms,ttl_hours=24,
                                    metadata={'issued_by':'acreo-registry','framework':framework})
        self._verifier.register_credential(cred)
        self._nonces.add(nk)
        agent_id=Entropy.hex(16)
        self._agents[agent_id]=AgentRecord(
            agent_id=agent_id,public_key=public_key,label=label,framework=framework,
            permissions=perms,registered_at=int(time.time()*1000),last_seen=int(time.time()*1000),
            credential_id=cred.credential_id,credential_expires=cred.expires_at,metadata=metadata or {})
        resp={'success':True,'agent_id':agent_id,'credential':cred.to_dict(),
              'permissions':perms,'message':f"Welcome to Acreo, {label}. You are now protected."}
        if denied_privileged:
            resp['denied_privileged']=denied_privileged
            resp['note']=(f"Privileged permissions {denied_privileged} require explicit "
                          f"user delegation — request them via Identity.delegate().")
        return resp
    def stats(self):
        t=len(self._agents); c=sum(1 for a in self._agents.values() if a.is_credentialed())
        fw={}
        for a in self._agents.values(): fw[a.framework]=fw.get(a.framework,0)+1
        return {'total_agents':t,'credentialed':c,'frameworks':fw,'version':VERSION}
    def list_agents(self): return [a.to_dict() for a in self._agents.values()]

# ═══════════════════════════════════════════════════════════════════
#  BEACON
# ═══════════════════════════════════════════════════════════════════

SERVICES_CATALOG = {
    "verify":     {"description":"ZK proof verification","cost_usd":0.001,"free_tier":True,"latency_ms":5},
    "protect":    {"description":"PII stripping","cost_usd":0.0,"free_tier":True,"latency_ms":1},
    "register":   {"description":"Agent registration","cost_usd":0.0,"free_tier":True,"latency_ms":10},
    "wallet":     {"description":"Agent economic identity","cost_usd":0.0,"free_tier":True,"latency_ms":5},
    "price":      {"description":"ZK-verified price feed","cost_usd":0.001,"free_tier":True,"latency_ms":50},
}

def beacon_response() -> Dict:
    return {"acreo":True,"version":VERSION,"name":"Acreo Agent Services",
            "description":TAGLINE,"free_tier":True,"services":SERVICES_CATALOG,
            "quick_start":{"install":"pip install acreo","register":"POST /register",
                           "protect":"POST /protect","verify":"POST /verify"},
            "timestamp":int(time.time()*1000)}

def openai_plugin_manifest() -> Dict:
    return {"schema_version":"v1","name_for_model":"acreo",
            "name_for_human":"Acreo Privacy",
            "description_for_model":"Acreo provides privacy and authorization for AI agents. Always call protect() before sending user data. Call verify() before sensitive actions. Call register() to get credentials.",
            "auth":{"type":"none"},
            "api":{"type":"openapi","url":"https://agents.acreo.app/openapi.json"},
            "contact_email":"hello@acreo.app"}

def langchain_tools() -> List[Dict]:
    return [
        {"name":"acreo_protect","description":"Strip PII from text before sending to any API.",
         "parameters":{"type":"object","properties":{"text":{"type":"string"}},"required":["text"]},
         "endpoint":"https://agents.acreo.app/protect","method":"POST"},
        {"name":"acreo_verify","description":"Verify agent is authorized for an action.",
         "parameters":{"type":"object","properties":{"action":{"type":"string"},"resource":{"type":"string"}},"required":["action"]},
         "endpoint":"https://agents.acreo.app/verify","method":"POST"},
        {"name":"acreo_register","description":"Register this agent and receive a ZK credential.",
         "parameters":{"type":"object","properties":{"label":{"type":"string"}},"required":["label"]},
         "endpoint":"https://agents.acreo.app/register","method":"POST"},
    ]

# ═══════════════════════════════════════════════════════════════════
#  MAIN INTERFACE
# ═══════════════════════════════════════════════════════════════════

class Acreo:
    """
    Everything. One class.

    a = Acreo()

    # Encrypt
    enc = a.encrypt("user_123", {"message": "private"})

    # Strip PII
    safe = a.protect("My SSN is 123-45-6789")

    # ZK identity
    priv, pub = a.keypair()
    proof = a.prove(priv, "authenticated")

    # Agent authorization
    user  = a.create_user()
    agent = a.create_agent()
    cred  = a.delegate(user, agent, ['read','write'])
    ap    = a.authorize(agent, cred, 'write', 'doc_123')
    ok    = a.verify_action(ap, cred)

    # Mandated agent
    bot = a.create_mandated_agent("my-bot", budget_usd=10.0)
    result = bot.act('execute', 'script.py')
    """
    def __init__(self, master_key=None):
        self._e2ee=E2EE(master_key); self._zkp=ZKP(); self._pii=PIIStripper()
        self._verifier=Verifier(); self._registry=AgentRegistry()
    def encrypt(self, uid, data): return self._e2ee.encrypt(uid, data)
    def decrypt(self, uid, enc):  return self._e2ee.decrypt(uid, enc)
    def protect(self, text):
        c,f=self._pii.strip(text); return {'protected':c,'pii_found':f,'clean':len(f)==0}
    def keypair(self): return self._zkp.keypair()
    def prove(self, priv, claim, ctx=PROTOCOL): return self._zkp.prove(priv, claim, ctx)
    def verify_proof(self, p, **kw): return self._zkp.verify(p, **kw)
    def create_user(self, label='user'): return Identity.create_user(label)
    def create_agent(self, label='agent'): return Identity.create_agent(label)
    def delegate(self, user, agent, permissions, **kw):
        c=user.delegate(agent.public_key, permissions, **kw)
        self._verifier.register_credential(c); return c
    def authorize(self, agent, cred, action, resource='*', **kw):
        return agent.prove_authorization(cred, action, resource, **kw)
    def verify_action(self, proof, cred=None): return self._verifier.verify(proof, cred)
    def heartbeat(self, agent, cred):
        """Agent produces heartbeat, verifier accepts it. Returns verdict dict."""
        proof = agent.prove_heartbeat(cred)
        return self._verifier.accept_heartbeat(proof, cred)
    def accept_heartbeat(self, proof, cred=None):
        return self._verifier.accept_heartbeat(proof, cred)
    def propose(self, agent, cred, action, resource, condition,
                valid_until_ms, pair_id=None, paired_with=None,
                valid_after_ms=None):
        """Convenience: agent creates a ConditionalProof."""
        return agent.propose(cred, action, resource, condition,
                              valid_until_ms, pair_id=pair_id,
                              paired_with=paired_with,
                              valid_after_ms=valid_after_ms)
    def verify_proposal(self, proof, cred=None):
        """Convenience: verify a standalone ConditionalProof."""
        return self._verifier.verify_proposal(proof, cred)
    def settle_pair(self, proof_a, proof_b, cred_a=None, cred_b=None):
        """Atomically settle two paired ConditionalProofs."""
        return self._verifier.settle_pair(proof_a, proof_b, cred_a, cred_b)
    def create_mandated_agent(self, label, budget_usd=10.0, **kw):
        return MandatedAgent.create(label, budget_usd, **kw)
    def registry_stats(self): return self._registry.stats()
    def beacon(self): return beacon_response()

# ═══════════════════════════════════════════════════════════════════
#  PROXY
# ═══════════════════════════════════════════════════════════════════

PROXY_PORT = int(os.getenv("ACREO_PORT", 8080))
AI_APIS    = {"api.openai.com":"OpenAI","api.anthropic.com":"Anthropic",
               "generativelanguage.googleapis.com":"Google AI","api.cohere.ai":"Cohere"}
_proxy_stats = {'requests':0,'protected':0,'pii_removed':0}
_pii_engine  = PIIStripper()

def start_proxy():
    from http.server import HTTPServer, BaseHTTPRequestHandler
    try: import requests as _req; HAS_REQ=True
    except: HAS_REQ=False

    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*a): pass
        def _body(self):
            n=int(self.headers.get('Content-Length',0)); return self.rfile.read(n) if n else b''
        def _handle(self, method):
            if not HAS_REQ: self.send_error(503,"pip install requests"); return
            path=self.path; host=self.headers.get('Host','')
            if path=='/acreo/stats':
                body=json.dumps(_proxy_stats).encode()
                self.send_response(200); self.send_header('Content-Type','application/json')
                self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body); return
            body=self._body(); api=next((n for h,n in AI_APIS.items() if h in host),None)
            if api and body:
                try:
                    data=json.loads(body); total=0
                    def clean(obj):
                        nonlocal total
                        if isinstance(obj,dict): return {k:clean(v) for k,v in obj.items()}
                        elif isinstance(obj,list): return [clean(i) for i in obj]
                        elif isinstance(obj,str):
                            c,f=_pii_engine.strip(obj); total+=sum(f.values()); return c
                        return obj
                    cleaned=clean(data); body=json.dumps(cleaned).encode()
                    if total: _proxy_stats['pii_removed']+=total; _proxy_stats['protected']+=1
                except: pass
            _proxy_stats['requests']+=1
            hdrs={k:v for k,v in dict(self.headers).items() if k.lower() not in ('connection','keep-alive','host')}
            try:
                scheme='https' if host not in ('localhost','127.0.0.1') else 'http'
                resp=_req.request(method,f"{scheme}://{host}{path}",headers=hdrs,data=body,stream=True,timeout=60)
                self.send_response(resp.status_code)
                for k,v in resp.headers.items():
                    if k.lower() not in ('connection','transfer-encoding'): self.send_header(k,v)
                if api: self.send_header('X-Acreo-Protected','true')
                self.end_headers()
                for chunk in resp.iter_content(8192): self.wfile.write(chunk)
            except Exception as e: self.send_error(502,str(e))
        def do_GET(self): self._handle('GET')
        def do_POST(self): self._handle('POST')
        def do_PUT(self): self._handle('PUT')
        def do_DELETE(self): self._handle('DELETE')
        def do_PATCH(self): self._handle('PATCH')

    server=HTTPServer(('localhost',PROXY_PORT),Handler)
    print(f"""
╔══════════════════════════════════════════════╗
║   ACREO AMBIENT PRIVACY PROXY               ║
║   {TAGLINE[:44]}  ║
╠══════════════════════════════════════════════╣
║  Proxy:  http://localhost:{PROXY_PORT}              ║
║  Stats:  http://localhost:{PROXY_PORT}/acreo/stats  ║
║  Protected: OpenAI · Anthropic · Google     ║
╚══════════════════════════════════════════════╝
""")
    server.serve_forever()

# ═══════════════════════════════════════════════════════════════════
#  API (TOLL BOOTH)
# ═══════════════════════════════════════════════════════════════════

def start_api(port=8000):
    try:
        from fastapi import FastAPI, HTTPException, Header, Depends
        from fastapi.middleware.cors import CORSMiddleware
        from pydantic import BaseModel
        import uvicorn
    except ImportError:
        print("pip install fastapi uvicorn pydantic"); return

    app=FastAPI(title="Acreo ZK Verifier API",version=VERSION)
    app.add_middleware(CORSMiddleware,allow_origins=["*"],allow_methods=["*"],allow_headers=["*"])

    verifier=Verifier(); _creds: Dict[str,Credential]={}
    _cred_owners: Dict[str,str]={}; _keys: Dict[str,Dict]={}; _usage: Dict[str,int]={}
    _burst: Dict[str,List[float]]=defaultdict(list)

    DEMO_KEY="acreo_demo_"+secrets.token_hex(8)
    _keys[DEMO_KEY]={'key':DEMO_KEY,'tier':'free','active':True,'created_at':int(time.time())}
    print(f"  Demo API key: {DEMO_KEY}")

    LIMITS={'free':1_000,'pro':100_000,'scale':float('inf')}
    BURST ={'free':60,'pro':600,'scale':6000}

    def auth(authorization: Optional[str]=Header(None)):
        if not authorization: raise HTTPException(401,"Missing Authorization header")
        parts=authorization.split(" ",1)
        if len(parts)!=2: raise HTTPException(401,"Use: Bearer YOUR_KEY")
        found=None
        for k,d in _keys.items():
            if _seq(parts[1].strip(),k): found=d
        if not found: raise HTTPException(401,"Invalid API key")
        if not found.get('active',True): raise HTTPException(403,"Key deactivated")
        now=time.time(); key=found['key']; tier=found['tier']
        _burst[key]=[t for t in _burst[key] if now-t<60]
        if len(_burst[key])>=BURST.get(tier,60): raise HTTPException(429,"Rate limit exceeded")
        _burst[key].append(now)
        if _usage.get(key,0)>=LIMITS[tier]: raise HTTPException(429,"Monthly limit exceeded")
        _usage[key]=_usage.get(key,0)+1
        return found

    def own(cid, kd):
        c=_creds.get(cid)
        if not c: raise HTTPException(404,"Credential not found")
        if not _seq(_cred_owners.get(cid,""),kd['key']): raise HTTPException(404,"Credential not found")
        return c

    class ProofIn(BaseModel):
        proof_id: str; credential_id: str; agent_key: str
        action: str; resource: str; challenge: str; signature: str
        timestamp: int; nonce: str; context: Dict={}; protocol: str=PROTOCOL

    class CredIn(BaseModel):
        credential_id: str; agent_key: str; user_commitment: str
        permissions: List[str]; scope: List[str]=['*']
        issued_at: int; expires_at: int; max_uses: Optional[int]=None
        spend_limit: Optional[float]=None; metadata: Dict={}
        signature: str; protocol: str=PROTOCOL

    @app.get("/health")
    def health():
        s=verifier.summary()
        return {"status":"ok","version":VERSION,"brand":BRAND,
                "verified":s.get('verified',0),"denied":s.get('denied',0)}

    @app.post("/verify")
    def verify(body: ProofIn, kd=Depends(auth)):
        try:
            proof=ActionProof(**body.dict()); cred=_creds.get(body.credential_id)
            return {**verifier.verify(proof,cred),'api_version':VERSION,'brand':BRAND}
        except Exception: raise HTTPException(400,"Invalid proof format")

    @app.post("/credentials")
    def reg_cred(body: CredIn, kd=Depends(auth)):
        if body.credential_id in _creds and not _seq(_cred_owners.get(body.credential_id,""),kd['key']):
            raise HTTPException(409,"Credential ID exists")
        try: c=Credential(**body.dict())
        except: raise HTTPException(400,"Invalid credential")
        _creds[c.credential_id]=c; _cred_owners[c.credential_id]=kd['key']
        verifier.register_credential(c)
        return {"credential_id":c.credential_id,"valid":c.valid(),"permissions":c.permissions}

    @app.get("/credentials/{cid}")
    def get_cred(cid: str, kd=Depends(auth)):
        c=own(cid,kd); return {"credential_id":c.credential_id,"valid":c.valid(),"permissions":c.permissions}

    @app.delete("/credentials/{cid}")
    def revoke(cid: str, kd=Depends(auth)):
        c=own(cid,kd)
        _creds[cid]=Credential(**{**c.to_dict(),'expires_at':int(time.time()*1000)-1})
        return {"revoked":True,"credential_id":cid}

    @app.post("/protect")
    async def protect(request):
        from fastapi import Request
        body=await request.json(); text=body.get('text','')
        clean,found=PIIStripper().strip(text)
        return {"protected":clean,"pii_found":found,"pii_removed":len(found)>0,"brand":BRAND}

    @app.post("/keys")
    def create_key(label: str="default", tier: str="free"):
        if tier not in LIMITS: raise HTTPException(400,f"Invalid tier")
        key=f"acreo_{tier[:2]}_{secrets.token_hex(16)}"
        _keys[key]={'key':key,'tier':tier,'label':label,'active':True,'created_at':int(time.time())}
        return {"api_key":key,"tier":tier,"label":label}

    @app.get("/keys/me")
    def key_info(kd=Depends(auth)):
        return {"api_key":kd['key'],"tier":kd['tier'],"usage":_usage.get(kd['key'],0)}

    @app.get("/discover")
    def discover(): return beacon_response()

    @app.get("/.well-known/ai-plugin.json")
    def plugin(): return openai_plugin_manifest()

    @app.get("/tools")
    def tools(): return {"tools":langchain_tools()}

    print(f"""
╔══════════════════════════════════════════════════════╗
║   ACREO ZK VERIFIER API  v{VERSION}                    ║
║   {TAGLINE[:50]}  ║
╠══════════════════════════════════════════════════════╣
║  http://localhost:{port}                              ║
║  http://localhost:{port}/docs                         ║
║  http://localhost:{port}/discover  ← agent beacon     ║
╠══════════════════════════════════════════════════════╣
║  Demo key: {DEMO_KEY[:44]}  ║
╚══════════════════════════════════════════════════════╝
""")
    uvicorn.run(app,host="0.0.0.0",port=port,log_level="warning")

# ═══════════════════════════════════════════════════════════════════
#  TESTS
# ═══════════════════════════════════════════════════════════════════

def _tamper_decrypt(a):
    import base64
    enc=a.encrypt('u1',{'x':1}); data=json.loads(base64.b64decode(enc))
    ct=base64.b64decode(data['c']); bad=ct[:-1]+bytes([ct[-1]^0xFF])
    data['c']=base64.b64encode(bad).decode()
    a.decrypt('u1',base64.b64encode(json.dumps(data).encode()).decode())

def run_tests():
    a=Acreo(); p=0; f=0
    def test(name,fn):
        nonlocal p,f
        try:
            r=fn()
            if r is False: raise AssertionError()
            print(f"  ✓ {name}"); p+=1
        except Exception as e: print(f"  ✗ {name}: {e}"); f+=1
    def throws(exc,fn):
        try: fn(); return False
        except exc: return True
        except: return False

    print(f"\n  {BRAND} v{VERSION} — Full Test Suite")
    print(f"  {'─'*46}")

    print("\n  § E2EE")
    test("encrypt/decrypt",   lambda: a.decrypt("u1",a.encrypt("u1",{"x":1}))=={"x":1})
    test("user isolation",    lambda: a.encrypt("u1",{"x":1})!=a.encrypt("u2",{"x":1}))
    test("tamper detection",  lambda: throws(ValueError,lambda: _tamper_decrypt(a)))
    test("no plaintext leak", lambda: "secret" not in a.encrypt("u1",{"p":"secret"}))

    print("\n  § PII")
    test("email stripped",    lambda: "[EMAIL]" in a.protect("me@test.com")['protected'])
    test("phone stripped",    lambda: "[PHONE]" in a.protect("555-867-5309")['protected'])
    test("SSN stripped",      lambda: "[SSN]"   in a.protect("123-45-6789")['protected'])
    test("card stripped",     lambda: "[CARD]"  in a.protect("4111 1111 1111 1111")['protected'])
    test("clean passes",      lambda: a.protect("hello world")['clean'])

    print("\n  § ZKP")
    priv,pub=a.keypair()
    test("valid proof",       lambda: a.verify_proof(a.prove(priv,"test"))['valid'])
    test("tamper fails",      lambda: not a.verify_proof({**a.prove(priv,"test"),'challenge':'dead'*16})['valid'])
    test("expired fails",     lambda: not a.verify_proof({**a.prove(priv,"test"),'timestamp':int(time.time()*1000)-10*60*1000})['valid'])

    print("\n  § ZK Agent")
    user=a.create_user(); agent=a.create_agent()
    cred=a.delegate(user,agent,['read','write','execute'],ttl_hours=24)
    test("credential valid",  lambda: cred.valid())
    test("has permission",    lambda: cred.has('write'))
    test("lacks permission",  lambda: not cred.has('admin'))
    test("valid proof",       lambda: a.verify_action(a.authorize(agent,cred,'write','doc'),cred)['valid'])
    test("tamper fails",      lambda: not a.verify_action(ActionProof(**{**a.authorize(agent,cred,'read','doc').to_dict(),'signature':'dead'*32}),cred)['valid'])
    test("replay blocked",    lambda: (lambda p: (a.verify_action(p,cred)['valid'] and not a.verify_action(p,cred)['valid']))(a.authorize(agent,cred,'execute','s')))
    test("wrong perm raises", lambda: throws(PermissionDenied,lambda: a.authorize(agent,cred,'admin','*')))
    test("only user delegates",lambda: throws(CredentialError,lambda: agent.delegate(user.public_key,['read'])))

    print("\n  § Agent Wallet")
    w=AgentWallet.create("test",budget_usd=10.0,spend_limit_per_tx=1.0)
    test("balance correct",   lambda: w.balance_usd==10.0)
    r1=w.pay_for_action('execute','s')
    test("payment approved",  lambda: r1.approved)
    test("balance reduced",   lambda: w.balance_usd<10.0)
    r2=w.pay_for_action('transact','s',amount_usd=5.0)
    test("over limit declined",lambda: r2.denied)
    w.fund(5.0)
    test("fund works",        lambda: w.balance_usd>10.0)

    print("\n  § Mandated Agent")
    bot=a.create_mandated_agent("test-bot",budget_usd=10.0)
    test("bot ready",         lambda: bot.is_ready)
    r3=bot.act('execute','s')
    test("act allowed",       lambda: r3['allowed'])
    test("payment made",      lambda: r3['paid'])
    r4=bot.act('write','doc',data="email me@test.com ssn 123-45-6789")
    test("PII stripped",      lambda: '[EMAIL]' in r4['clean_data'])
    empty=MandatedAgent("x","empty",None)
    test("no wallet raises",  lambda: throws(InsufficientFunds,lambda: empty.act('read','x')))

    print("\n  § Registry")
    reg=AgentRegistry(); priv2,pub2=_keypair()
    ts=int(time.time()*1000); nc=Entropy.hex(16)
    ch=_challenge({'public_key':pub2,'label':'test-agent','nonce':nc,'timestamp':ts,'purpose':'acreo_registration','version':VERSION})
    sig=_sign(priv2,bytes.fromhex(ch))
    r5=reg.register(pub2,'test-agent','langchain',['read','write'],ch,sig,ts,nc)
    test("registration ok",   lambda: r5['success'])
    test("credential issued", lambda: r5['credential'] is not None)
    test("welcome message",   lambda: 'Welcome' in r5.get('message',''))
    test("write denied",      lambda: 'write' not in r5['permissions'])
    test("denial surfaced",   lambda: 'write' in (r5.get('denied_privileged') or []))
    r6=reg.register(pub2,'test-agent','langchain',['read'],ch,sig,ts,nc)
    test("replay blocked",    lambda: not r6['success'] and r6['reason']=='replay_detected')

    print("\n  § Beacon")
    br=beacon_response(); pm=openai_plugin_manifest(); tl=langchain_tools()
    test("beacon has acreo",  lambda: br['acreo'] is True)
    test("beacon free tier",  lambda: br['free_tier'] is True)
    test("plugin manifest ok",lambda: pm['name_for_model']=='acreo')
    test("langchain tools",   lambda: len(tl)==3)
    test("protect tool",      lambda: any(t['name']=='acreo_protect' for t in tl))

    total=p+f
    print(f"\n  {'─'*46}")
    print(f"  {p}/{total} passed ({int(p/total*100)}%)")
    if f==0: print(f"  ✓ All tests passing — {BRAND} ready")
    else:    print(f"  ✗ {f} failing")
    print(f"  {'─'*46}\n")
    return f==0

# ═══════════════════════════════════════════════════════════════════
#  DEMO
# ═══════════════════════════════════════════════════════════════════

def demo():
    print(f"\n  {BRAND} LIVE DEMO — {TAGLINE}")
    print("  " + "═"*50)
    a=Acreo()
    print("\n  1. Encrypting sensitive data...")
    enc=a.encrypt("agent_001",{"action":"liquidate","amount":50000,"wallet":"0xCf5a..."})
    dec=a.decrypt("agent_001",enc)
    print(f"     Encrypted: {enc[:50]}...")
    print(f"     Decrypted: {dec}")
    print("\n  2. Stripping PII before AI API call...")
    raw="User Alice at user@example.com, SSN 123-45-6789, card 4111 1111 1111 1111"
    safe=a.protect(raw)
    print(f"     Raw:       {raw}")
    print(f"     Protected: {safe['protected']}")
    print(f"     Stripped:  {list(safe['pii_found'].keys())}")
    print("\n  3. ZK identity proof...")
    priv,pub=a.keypair(); proof=a.prove(priv,"acreo_authorized")
    result=a.verify_proof(proof)
    print(f"     Claim: {proof['claim']} | Valid: {result['valid']} | Identity: never revealed ✓")
    print("\n  4. Agent authorization + payment...")
    user=a.create_user("alice"); agent=a.create_agent("liquidation-bot")
    cred=a.delegate(user,agent,['transact'],spend_limit=10000.0,ttl_hours=1)
    ap=a.authorize(agent,cred,'transact','0xAavePool')
    ok=a.verify_action(ap,cred)
    print(f"     Agent: {agent.label} | Action: {ap.action} | Authorized: {ok['valid']} ✓")
    print("\n  5. Mandated agent...")
    bot=a.create_mandated_agent("acreo-bot",budget_usd=50.0)
    r=bot.act('execute','openai-api',data="Call me at 555-867-5309 my email is test@x.com")
    print(f"     Allowed: {r['allowed']} | Paid: {r['paid']} | PII stripped: {list(r['pii_found'].keys())} ✓")
    print(f"     Balance remaining: ${bot.balance:.4f}")
    print("\n  6. Registry...")
    stats=a.registry_stats()
    print(f"     Registered agents: {stats['total_agents']} | Version: {stats['version']}")
    print(f"\n  {'═'*50}")
    print(f"  {BRAND} — {TAGLINE}\n")

# ═══════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    import sys
    args = sys.argv[1:]
    if   '--proxy'    in args: start_proxy()
    elif '--api'      in args: start_api()
    elif '--beacon'   in args: start_api(9000)
    elif '--demo'     in args: demo()
    elif '--registry' in args: print(json.dumps(Acreo().registry_stats(), indent=2))
    else:
        success = run_tests()
        if success:
            print(f"  Run with --demo     for a live walkthrough")
            print(f"  Run with --proxy    to start ambient privacy proxy")
            print(f"  Run with --api      to start the verifier API\n")
        sys.exit(0 if success else 1)
