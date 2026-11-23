"""WBS 2.2-A: abstract, monotone, deterministic attacker-fact closure.

This is a *prototype*, not a path enumerator, vulnerability checker or probability model.
The caller must pass already validated IR. Unknown configuration is not treated as
permission or exploitation evidence. All rule results record their dependencies.
"""
from __future__ import annotations
from dataclasses import dataclass
from collections import defaultdict
from typing import Any, Iterable, Mapping
import json
import hashlib

LEVEL = {'none': 0, 'restricted': 1, 'user': 2, 'admin': 3, 'system': 4}


def value(x: Any) -> Any:
    """Return an Attr's value, while leaving structured non-Attr dictionaries intact."""
    if isinstance(x, dict) and 'value' in x and (set(x) & {'source', 'confidence', 'distribution'}):
        return x['value']
    return x


def get(obj: Mapping, name: str, default: Any = None) -> Any:
    return value(obj.get(name, default))


def item_id(x: Any) -> str:
    x = value(x)
    return str(x.get('id', '')) if isinstance(x, dict) else str(x)


@dataclass(frozen=True, order=True)
class Fact:
    kind: str
    args: tuple[str, ...]

    def __init__(self, kind: str, *args: Any):
        if kind not in {'foothold', 'acts_as', 'has_credential', 'controls', 'data_access', 'knows'}:
            raise ValueError(f'unsupported fact: {kind}')
        object.__setattr__(self, 'kind', kind)
        object.__setattr__(self, 'args', tuple(map(str, args)))

    def as_dict(self) -> dict:
        return {'kind': self.kind, 'args': list(self.args)}


@dataclass(frozen=True, order=True)
class Derivation:
    rule: str
    premises: tuple[Fact, ...] = ()
    evidence: tuple[str, ...] = ()

    def as_dict(self) -> dict:
        return {'rule': self.rule, 'premises': [p.as_dict() for p in self.premises],
                'evidence': list(self.evidence)}


class ThinEngine:
    def __init__(self, ir: Mapping[str, Any], *, knowledge: str = 'informed'):
        if knowledge not in {'informed', 'uninformed'}:
            raise ValueError('knowledge must be informed or uninformed')
        self.profile_ids: set[str] = set()
        encoded = json.dumps(ir, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)
        self.input_revision = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        self.ir = ir
        self.knowledge = knowledge
        self.assets = {item_id(a['id']): a for a in ir.get('assets', [])}
        self.groups = {item_id(g['id']): g for g in ir.get('groups', [])}
        self.rels = sorted(ir.get('relations', []), key=lambda r: json.dumps(r, sort_keys=True, default=str))
        self.facts: set[Fact] = set()
        self.proofs: dict[Fact, set[Derivation]] = defaultdict(set)
        self.exposure_evidence = set()
        self.blocked: list[str] = []

    def add(self, fact: Fact, proof: Derivation | None = None) -> bool:
        fresh = fact not in self.facts
        self.facts.add(fact)
        if proof is not None:
            self.proofs[fact].add(proof)
        return fresh

    def has(self, fact: Fact) -> bool:
        if fact in self.facts: return True
        if fact.kind == 'foothold':
            asset, required = fact.args
            return any(f.kind == 'foothold' and f.args[0] == asset and
                       LEVEL.get(f.args[1], -1) >= LEVEL.get(required, 99) for f in self.facts)
        return False

    def knows(self, target: str) -> bool:
        return self.knowledge == 'informed' or self.has(Fact('knows', target))

    def confirmed(self, rel: Mapping) -> bool:
        return get(rel, 'source', 'declared') == 'declared' and get(rel, 'confidence', 1.0) == 1.0

    def reltype(self, rel: Mapping) -> str:
        return str(get(rel, 'type', ''))

    def src(self, rel: Mapping) -> str:
        return item_id(get(rel, 'from', get(rel, 'source', '')))

    def dst(self, rel: Mapping) -> str:
        return item_id(get(rel, 'to', get(rel, 'target', '')))

    def rel_id(self, rel: Mapping) -> str:
        return 'relation:' + hashlib.sha256(json.dumps(rel, sort_keys=True, ensure_ascii=False, default=str).encode('utf-8')).hexdigest()[:16]

    def attr(self, rel: Mapping, field: str, default: Any = None) -> Any:
        # schema can express type-specific values as flat fields or nested object
        if field in rel: return get(rel, field, default)
        nested = rel.get(self.reltype(rel), {})
        if isinstance(nested, Mapping): return get(nested, field, default)
        return default

    def group_chain(self, group: str) -> set[str]:
        seen = set()
        todo = [group]
        while todo:
            gid = todo.pop()
            if gid in seen: continue
            seen.add(gid)
            if gid in self.groups:
                p = get(self.groups[gid], 'parent')
                if p: todo.append(item_id(p))
        return seen

    def memberships(self, asset: str) -> set[str]:
        data = self.assets.get(asset, {})
        return {'group:' + g for name in (get(data, 'groups', []) or []) for g in self.group_chain(item_id(name))}

    def matches(self, endpoint: str, actual: str) -> bool:
        return endpoint == actual or endpoint in self.memberships(actual)

    def reachable(self, target: str) -> tuple[Fact, ...] | None:
        """Conservative direct reachability from an existing foothold.

        Group endpoints accepted. No invented route, transitivity, via or NAT.
        A direct self-host reach is allowed. Granular port/protocol checks are
        intentionally deferred; unsupported constraints fail closed.
        """
        for f in sorted(self.facts):
            if f.kind != 'foothold': continue
            if f.args[0] == target: return (f,)
            for r in self.rels:
                if self.reltype(r) != 'reaches' or not self.confirmed(r): continue
                if self.attr(r, 'via') not in (None, [], ''): continue
                if self.matches(self.src(r), f.args[0]) and self.matches(self.dst(r), target):
                    return (f,)
        return None

    def seed(self, facts: Iterable[Fact]) -> None:
        for f in facts: self.add(f, Derivation('SEED'))

    def seed_profile(self, profile: Mapping[str, Any]) -> None:
        if profile.get('id'):
            self.profile_ids.add(item_id(profile['id']))
        priv = str(get(profile, 'initial_privilege', 'none'))
        for start in get(profile, 'start', []) or []:
            asset = item_id(start)
            level = 'none' if self.assets.get(asset, {}).get('type') == 'external' else priv
            self.add(Fact('foothold', asset, level), Derivation('SEED_PROFILE', evidence=(f'profile:{get(profile,"id", "unknown")}',)))
            if self.knowledge == 'uninformed': self.add(Fact('knows', asset), Derivation('SEED_KNOWLEDGE'))
            if level != 'none':
                for r in self.rels:
                    if self.reltype(r) == 'session' and self.dst(r) == asset and self.confirmed(r):
                        self.add(Fact('acts_as', self.src(r)), Derivation('SEED_SESSION', (Fact('foothold', asset, level),), (self.rel_id(r),)))
        # known_state is deliberately not initialized: may be probabilistic.

    def apply(self) -> None:
        """Apply R1-R11 once; repeated by run() until a fixed point."""
        old = sorted(self.facts)
        rels = self.rels
        for r in rels:
            typ, src, dst = self.reltype(r), self.src(r), self.dst(r)
            rid = self.rel_id(r)
            if not self.confirmed(r):
                continue
            if typ == 'member_of':  # R1
                for f in old:
                    if f == Fact('acts_as', src):
                        self.add(Fact('acts_as', dst), Derivation('R1', (f,), (rid,)))
            if typ == 'authenticates_to':  # R2
                for f in old:
                    if f == Fact('acts_as', src) and self.knows(dst):
                        reach = self.reachable(dst)
                        if reach:
                            level = str(self.attr(r, 'privilege', 'user'))
                            if level not in LEVEL: continue
                            self.add(Fact('foothold', dst, level), Derivation('R2', (f, *reach), (rid,)))
            if typ == 'has_permission':  # R3: only explicit allowed actions
                if str(self.attr(r, 'effect', 'allow')) != 'allow': continue
                # Deny takes precedence for an identical principal/target/action.
                if any(self.reltype(d) == 'has_permission' and self.src(d) == src
                           and self.dst(d) == dst and
                           str(self.attr(d, 'action', '')) == str(self.attr(r, 'action', ''))
                           and str(self.attr(d, 'effect', 'allow')) == 'deny'
                           for d in rels): continue
                if self.attr(r, 'condition') not in (None, '', {}): continue
                action = str(self.attr(r, 'action', ''))
                for f in old:
                    if f != Fact('acts_as', src): continue
                    if not self.knows(dst): continue
                    if action in ('admin', 'manage', 'execute', 'write', 'read'):
                        if dst.startswith('group:') and dst[6:] in self.groups and action in ('admin', 'manage'):
                            new = Fact('controls', dst)
                        elif self.assets.get(dst, {}).get('type') == 'data' and action in ('read', 'write'):
                            new = Fact('data_access', dst, action)
                        elif action in ('admin', 'manage', 'execute'):
                            new = Fact('foothold', dst, 'admin' if action in ('admin', 'manage') else 'user')
                        else:
                            continue  # read/write on store does not prove host execution
                        self.add(new, Derivation('R3', (f,), (rid,)))
            if typ == 'runs':  # R4: service on host; require explicit run-as
                identity = self.attr(r, 'as')
                if identity:
                    for f in old:
                        if f.kind == 'foothold' and LEVEL.get(f.args[1], 0) >= 3 and f.args[0] == src:
                            self.add(Fact('acts_as', item_id(identity)), Derivation('R4', (f,), (rid,)))
            if typ == 'session':  # R5: session relation host/service <-> identity
                for f in old:
                    if f.kind != 'foothold' or LEVEL.get(f.args[1], 0) < 3: continue
                    if f.args[0] == dst and src in self.assets and str(get(self.assets[src], 'type', '')) == 'identity':
                        self.add(Fact('acts_as', src), Derivation('R5', (f,), (rid,)))
            if typ == 'stores':  # R6
                for f in old:
                    if f.kind == 'foothold' and f.args[0] == src and LEVEL.get(f.args[1], 0) >= 3:
                        if str(get(self.assets.get(dst, {}), 'type')) == 'credential':
                            self.add(Fact('has_credential', dst), Derivation('R6', (f,), (rid,)))
            if typ == 'grants':  # R7
                for f in old:
                    if f == Fact('has_credential', src):
                        self.add(Fact('acts_as', dst), Derivation('R7', (f,), (rid,)))
            if typ == 'contains':  # R9, require explicit unencrypted / no key condition
                if self.attr(r, 'encrypted') is not False: continue  # unknown encryption is not plaintext
                if self.attr(r, 'key_ref'): continue
                host_sources = {src}
                for h in rels:
                    if self.reltype(h) == 'hosts' and self.confirmed(h) and self.dst(h) == src: host_sources.add(self.src(h))
                for f in old:
                    if f.kind == 'foothold' and f.args[0] in host_sources and LEVEL.get(f.args[1], 0) >= 3:
                        for mode in ('read', 'write'):
                            self.add(Fact('data_access', dst, mode), Derivation('R9', (f,), (rid,)))
            if typ == 'manages':
                for f in old:
                    if f.kind != 'foothold' or f.args[0] != src or LEVEL.get(f.args[1], 0) < 3:
                        continue
                    if dst.startswith('group:') and dst[6:] in self.groups:  # R8
                        self.add(Fact('controls', dst), Derivation('R8', (f,), (rid,)))
                    elif dst in self.assets:  # R11
                        self.add(Fact('foothold', dst, 'admin'), Derivation('R11', (f,), (rid,)))
        # R10 is explicitly a *candidate*, not a proven compromise. It must not
        # be inferred as deterministic truth without a success model (P3/P4).
        # Here we only record candidates without adding foothold facts.
        for r in rels:
            if self.reltype(r) != 'reaches': continue
            ext = self.assets.get(self.src(r), {})
            if ext.get('type') != 'external' or not any(f.kind == 'foothold' and f.args[0] == self.src(r) for f in self.facts): continue
            endpoint = self.dst(r)
            for asset_id, asset in sorted(self.assets.items()):
                if asset.get('type') != 'service' or not self.knows(asset_id): continue
                hosted = [host for host in rels if self.reltype(host) == 'runs'
                          and self.dst(host) == asset_id and self.confirmed(host)]
                if not hosted: continue
                if not any(self.matches(endpoint, self.src(host)) for host in hosted): continue
                ports = self.attr(r, 'ports')
                if ports and asset.get('port') not in ports: continue
                protocol = self.attr(r, 'protocol')
                if protocol not in (None, 'any', asset.get('protocol')): continue
                for host in hosted:
                    if self.matches(endpoint, self.src(host)):
                        self.exposure_evidence.add((asset_id, self.rel_id(r), self.rel_id(host),
                                                    self.attr(r, 'via') or ''))
                msg = f'R10 candidate: {self.src(r)} -> {asset_id} (requires success assumption)'
                if msg not in self.blocked: self.blocked.append(msg)

    def run(self, *, max_rounds: int = 100) -> dict:
        for index in range(max_rounds):
            before = len(self.facts)
            self.apply()
            if len(self.facts) == before:
                return self.report(index + 1)
        raise RuntimeError('fixed point not reached; max_rounds exceeded')

    def assessments(self) -> list[dict]:
        records = []
        for relation in self.rels:
            target = self.dst(relation)
            if self.assets.get(target, {}).get('type') != 'data_store':
                continue
            kind = self.reltype(relation)
            if kind == 'hosts' and self.confirmed(relation):
                status, reason = 'confirmed', '입력에 선언된 저장소 배치'
            elif (kind == 'has_permission' and self.attr(relation, 'action') == 'write'
                  and self.attr(relation, 'effect', 'allow') == 'allow'):
                status, reason = 'unevaluated', '저장소 쓰기 권한의 개별 데이터 적용 범위 미정'
            else:
                continue
            records.append(dict(status=status, subject=target, relation=kind, rule=kind,
                                evidence=[self.rel_id(relation)], reason=reason))
        for service, reach, host, via in sorted(self.exposure_evidence):
            question = f'{via}의 전달 설정 확인' if via else '서비스 외부 노출 여부 확인'
            records.append(dict(status='candidate', subject=service, rule='R10',
                                evidence=[reach, host], question=question))
        for record in records:
            record.update(rule_version=1, input_revision=self.input_revision,
                          profile_ids=sorted(self.profile_ids) if record["rule"] == "R10" else [])
        return records

    def report(self, rounds: int) -> dict:
        return {'assessments': self.assessments(), 'rounds': rounds, 'facts': [f.as_dict() for f in sorted(self.facts)],
                'derivations': [{'fact': f.as_dict(), 'alternatives': [d.as_dict() for d in sorted(self.proofs[f])]}
                                for f in sorted(self.facts)],
                'unresolved_candidates': sorted(self.blocked),
                'limitations': ['R10 probability unresolved', 'reachability direct only',
                                'conditional permissions excluded', 'unknown and probabilistic known_state excluded',
                                'not a P3 DAG or probability engine']}
