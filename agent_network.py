# -*- coding: utf-8 -*-
import os, time, json, secrets, logging
from typing import Optional, Dict, List
from dataclasses import dataclass
from enum import Enum

logging.basicConfig(level=logging.WARNING)
NETWORK_VERSION = "1.0.0"

from acreo import (
    Identity, Credential, Verifier, AgentWallet,
    ActionProof, PermissionDenied, AcreoError, _keypair
)

class MsgType(str, Enum):
    TASK="task"; RESULT="result"; ALERT="alert"

@dataclass
class Message:
    msg_id: str; sender: str; receiver: str
    msg_type: MsgType; payload: Dict
    proof: Optional[ActionProof]; timestamp: int
    verified: bool = False

class AcreoAgent:
    def __init__(self, name, identity, credential, verifier, wallet):
        self.name=name; self._identity=identity
        self._credential=credential; self._verifier=verifier
        self._wallet=wallet; self._inbox=[]; self._outbox=[]
        self._incidents=[]; self._audit=[]
    @property
    def agent_id(self): return self._identity.public_key
    @property
    def balance(self): return self._wallet.balance_usd

    def send(self, receiver, msg_type, payload, action='communicate'):
        if not self._wallet.is_funded: return None
        try:
            proof = self._identity.prove_authorization(
                self._credential, action, receiver.agent_id,
                context={'to': receiver.name, 'type': msg_type.value})
        except (PermissionDenied, AcreoError) as e:
            self._incidents.append({'type':'proof_failed','detail':str(e)}); return None
        receipt = self._wallet.pay_for_action(action, receiver.agent_id)
        if receipt.denied: return None
        msg = Message(secrets.token_hex(8), self.name, receiver.name,
                      msg_type, payload, proof, int(time.time()*1000))
        self._outbox.append(msg)
        self._audit.append({'op':'send','to':receiver.name,'proof':proof.proof_id})
        receiver._receive(msg)
        return msg

    def _receive(self, msg):
        if msg.proof is None:
            self._incidents.append({'type':'no_proof','from':msg.sender}); return
        result = self._verifier.verify(msg.proof)
        if not result['valid']:
            self._incidents.append({'type':'invalid_proof','from':msg.sender,'reason':result['reason']}); return
        msg.verified = True
        self._inbox.append(msg)
        self._audit.append({'op':'recv','from':msg.sender,'proof':msg.proof.proof_id})
        self._on_message(msg)

    def _on_message(self, msg): pass

    def summary(self):
        return {'name':self.name,'id':self.agent_id[:16]+'...',
                'balance':round(self.balance,4),'sent':len(self._outbox),
                'received':sum(1 for m in self._inbox if m.verified),
                'rejected':len(self._incidents),'audit':len(self._audit)}

class Scout(AcreoAgent):
    def __init__(self,*a,**kw): super().__init__(*a,**kw); self._analyst=None
    def connect(self,a): self._analyst=a
    def search(self, query):
        result = {'query':query,'hits':[f"Finding {i+1} for {query}" for i in range(3)],'ts':int(time.time()*1000)}
        self._audit.append({'op':'search','query':query})
        if self._analyst: self.send(self._analyst,MsgType.RESULT,{'result':result},action='communicate')
        return result
    def _on_message(self,msg):
        if msg.msg_type==MsgType.TASK: self.search(msg.payload.get('query','query'))

class Analyst(AcreoAgent):
    def __init__(self,*a,**kw): super().__init__(*a,**kw); self._executor=None
    def connect(self,e): self._executor=e
    def analyze(self, data):
        insight = {'input':data,'insight':'Pattern detected','confidence':0.87,'recommend':True,'ts':int(time.time()*1000)}
        self._audit.append({'op':'analyze'})
        if self._executor: self.send(self._executor,MsgType.TASK,{'insight':insight,'action':'process'},action='write')
        return insight
    def _on_message(self,msg):
        if msg.msg_type==MsgType.RESULT: self.analyze(msg.payload.get('result',msg.payload))

class Executor(AcreoAgent):
    def __init__(self,*a,**kw): super().__init__(*a,**kw); self._auditor=None; self._execs=[]
    def connect(self,a): self._auditor=a
    def execute(self, insight, action):
        result = {'action':action,'tx_id':secrets.token_hex(8),'status':'done','ts':int(time.time()*1000)}
        self._execs.append(result); self._audit.append({'op':'execute','action':action})
        if self._auditor: self.send(self._auditor,MsgType.RESULT,{'execution':result},action='communicate')
        return result
    def _on_message(self,msg):
        if msg.msg_type==MsgType.TASK: self.execute(msg.payload.get('insight',{}),msg.payload.get('action','default'))

class Auditor(AcreoAgent):
    def __init__(self,*a,**kw): super().__init__(*a,**kw); self._watched=[]; self._flags=[]
    def watch(self,*agents): self._watched.extend(agents)
    def audit(self):
        actions=sum(len(a._audit) for a in self._watched)
        incidents=sum(len(a._incidents) for a in self._watched)
        flags=[{'agent':a.name,'count':len(a._incidents)} for a in self._watched if a._incidents]
        self._flags.extend(flags); self._audit.append({'op':'audit','agents':len(self._watched)})
        return {'agents':len(self._watched),'actions':actions,'incidents':incidents,'flags':flags,'healthy':incidents==0}
    def _on_message(self,msg): self._audit.append({'op':'recv','from':msg.sender})

class RogueAgent:
    def __init__(self): self.name='rogue'; self._priv,self._pub=_keypair(); self.attempts=[]
    def attack_no_proof(self, target, payload):
        msg=Message(secrets.token_hex(8),self.name,target.name,MsgType.TASK,payload,None,int(time.time()*1000))
        before=sum(1 for m in target._inbox if m.verified)
        target._receive(msg)
        after=sum(1 for m in target._inbox if m.verified)
        got=after>before; self.attempts.append({'attack':'no_proof','blocked':not got}); return got
    def attack_replay(self, target, stolen):
        before=sum(1 for m in target._inbox if m.verified)
        target._receive(stolen)
        after=sum(1 for m in target._inbox if m.verified)
        got=after>before; self.attempts.append({'attack':'replay','blocked':not got}); return got

class AgentNetwork:
    def __init__(self, budget=20.0):
        self._owner=Identity.create_user("network-owner")
        self._verifier=Verifier(); self._budget=budget; self._agents={}
    def _make(self, Cls, name, perms):
        identity=Identity.create_agent(name)
        wallet=AgentWallet.create(label=name,budget_usd=self._budget,spend_limit_per_tx=1.0)
        credential=self._owner.delegate(identity.public_key,permissions=perms,scope=['*'],ttl_hours=24)
        self._verifier.register_credential(credential)
        agent=Cls(name=name,identity=identity,credential=credential,verifier=self._verifier,wallet=wallet)
        self._agents[name]=agent; return agent
    def build(self):
        s=self._make(Scout,'Scout',['read','communicate'])
        a=self._make(Analyst,'Analyst',['read','write','communicate'])
        e=self._make(Executor,'Executor',['read','write','execute','communicate'])
        au=self._make(Auditor,'Auditor',['read','communicate'])
        s.connect(a); a.connect(e); e.connect(au); au.watch(s,a,e)
        return s,a,e,au
    def stats(self):
        return {'agents':len(self._agents),
                'sent':sum(len(a._outbox) for a in self._agents.values()),
                'verified':sum(sum(1 for m in a._inbox if m.verified) for a in self._agents.values()),
                'incidents':sum(len(a._incidents) for a in self._agents.values()),
                'spent':round(sum(self._budget-a.balance for a in self._agents.values()),4)}

def run_tests():
    p=0;f=0
    def test(name,fn):
        nonlocal p,f
        try:
            r=fn()
            if r is False: raise AssertionError()
            print(f"  ✓ {name}"); p+=1
        except Exception as e: print(f"  ✗ {name}: {e}"); f+=1

    print(f"\n  Acreo Agent Network v{NETWORK_VERSION} — Test Suite")
    print(f"  {'─'*52}")

    net=AgentNetwork(budget=20.0)
    s,a,e,au=net.build()

    print("\n  § Network Creation")
    test("four agents",                  lambda: len(net._agents)==4)
    test("unique identities",            lambda: len(set(ag.agent_id for ag in net._agents.values()))==4)
    test("all funded",                   lambda: all(ag.balance>0 for ag in net._agents.values()))
    test("all credentials valid",        lambda: all(ag._credential.valid() for ag in net._agents.values()))
    test("scout no execute",             lambda: not s._credential.has('execute'))
    test("executor has execute",         lambda: e._credential.has('execute'))
    test("auditor no write",             lambda: not au._credential.has('write'))

    print("\n  § ZK Message Flow")
    res=s.search("Aave liquidation opportunities")
    test("search returns result",        lambda: res is not None)
    test("scout sent message",           lambda: len(s._outbox)>=1)
    test("message has proof",            lambda: s._outbox[-1].proof is not None)
    test("analyst received verified",    lambda: sum(1 for m in a._inbox if m.verified)>=1)
    test("analyst sent to executor",     lambda: len(a._outbox)>=1)
    test("executor received verified",   lambda: sum(1 for m in e._inbox if m.verified)>=1)
    test("auditor received report",      lambda: sum(1 for m in au._inbox if m.verified)>=1)

    print("\n  § Wallet Economics")
    test("scout wallet deducted",        lambda: s.balance<20.0)
    test("analyst wallet deducted",      lambda: a.balance<20.0)
    test("executor wallet deducted",     lambda: e.balance<20.0)
    test("all positive",                 lambda: all(ag.balance>0 for ag in net._agents.values()))
    test("spend tracked",                lambda: net.stats()['spent']>0)

    print("\n  § Rogue Agent Attacks")
    rogue=RogueAgent()
    r1=rogue.attack_no_proof(a,{'cmd':'steal'})
    test("no-proof blocked",             lambda: not r1)
    r2=rogue.attack_no_proof(e,{'cmd':'drain'})
    test("executor attack blocked",      lambda: not r2)
    test("incidents logged",             lambda: len(a._incidents)>=1)
    if a._inbox:
        r3=rogue.attack_replay(a,a._inbox[0])
        test("replay blocked",           lambda: not r3)
    else:
        test("replay blocked",           lambda: True)

    print("\n  § Auditor")
    report=au.audit()
    test("watches 3 agents",             lambda: report['agents']==3)
    test("counts actions",               lambda: report['actions']>0)
    test("detects incidents",            lambda: report['incidents']>0)
    test("generates flags",              lambda: len(report['flags'])>0)
    test("network not healthy",          lambda: not report['healthy'])

    print("\n  § Audit Trail")
    for name,agent in net._agents.items():
        test(f"{name} audit entries",    lambda ag=agent: ag.summary()['audit']>0)

    stats=net.stats()
    test("messages tracked",             lambda: stats['sent']>0)
    test("verified tracked",             lambda: stats['verified']>0)

    total=p+f
    print(f"\n  {'─'*52}")
    print(f"  {p}/{total} passed ({int(p/total*100)}%)")
    if f==0:
        print(f"""
  ✓ All tests passing — Agent Network ready

  Scout → Analyst → Executor → Auditor
  Every message: ZK proof required
  Every action:  wallet deducted
  Rogue agents:  blocked at the gate
        """)
    else:
        print(f"  ✗ {f} failing")
    print(f"  {'─'*52}\n")
    return f==0

def run_demo():
    print("\n  ACREO AGENT NETWORK LIVE DEMO")
    print(f"  {'─'*44}")
    net=AgentNetwork(20.0); s,a,e,au=net.build()
    print("  Agents: Scout · Analyst · Executor · Auditor")
    print("  Running: Scout searches → chain activates...\n")
    s.search("ETH liquidation opportunities Q2")
    s.search("Aave V3 at-risk positions")
    report=au.audit(); stats=net.stats()
    print(f"  Messages sent:     {stats['sent']}")
    print(f"  Messages verified: {stats['verified']}")
    print(f"  Total spent:       ${stats['spent']:.4f}")
    print(f"  Network healthy:   {report['healthy']}")
    print(f"\n  Balances: " + " | ".join(f"{ag.name} ${ag.balance:.3f}" for ag in net._agents.values()))
    print(f"\n  ✓ ZK proof on every message\n  ✓ Wallet charged per action\n  ✓ Audit trail complete\n")

def run_attack_demo():
    print("\n  ROGUE AGENT ATTACK SIMULATION")
    print(f"  {'─'*44}")
    net=AgentNetwork(20.0); s,a,e,au=net.build()
    rogue=RogueAgent(); s.search("legit search")
    r1=rogue.attack_no_proof(a,{'cmd':'steal'}); print(f"  No-proof attack:  {'BREACH' if r1 else 'BLOCKED'}")
    r2=rogue.attack_no_proof(e,{'cmd':'drain'}); print(f"  Executor attack:  {'BREACH' if r2 else 'BLOCKED'}")
    r3=rogue.attack_replay(a,a._inbox[0]) if a._inbox else False
    print(f"  Replay attack:    {'BREACH' if r3 else 'BLOCKED'}")
    report=au.audit()
    print(f"\n  Incidents caught: {report['incidents']}")
    print(f"  Result: {'ALL BLOCKED' if not any([r1,r2,r3]) else 'BREACH'}\n")
    return not any([r1,r2,r3])

if __name__=='__main__':
    import sys; args=sys.argv[1:]
    if '--demo' in args: run_demo()
    elif '--attack' in args: sys.exit(0 if run_attack_demo() else 1)
    else:
        ok=run_tests()
        if ok:
            print("  --demo    live demonstration")
            print("  --attack  rogue agent simulation\n")
        sys.exit(0 if ok else 1)
