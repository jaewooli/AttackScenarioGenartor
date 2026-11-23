"""Isolated deterministic tests, not a substitute for full repo integration."""
from scengen.thin_engine import ThinEngine, Fact


def ir():
    return {'groups':[{'id':'domain','kind':'directory_domain'}],
            'assets':[{'id':'web','type':'host'}, {'id':'outside','type':'external'}, {'id':'admin','type':'host','role':'domain_controller','groups':['domain']},
                      {'id':'store','type':'data_store'}, {'id':'pii','type':'data'},
                      {'id':'cred','type':'credential'}, {'id':'alice','type':'identity'}, {'id':'bob','type':'identity'},
                      {'id':'svc','type':'service','port':443,'protocol':'tcp'}],
            'relations':[
                {'id':'1','type':'member_of','from':'alice','to':'bob'},
                {'id':'2','type':'authenticates_to','from':'bob','to':'admin','privilege':'admin'},
                {'id':'3','type':'reaches','from':'web','to':'admin'},
                {'id':'4','type':'hosts','from':'admin','to':'store'},
                {'id':'5','type':'contains','from':'store','to':'pii','encrypted':False},
                {'id':'6','type':'stores','from':'admin','to':'cred'},
                {'id':'7','type':'grants','from':'cred','to':'alice'},
                {'id':'8','type':'manages','from':'admin','to':'web'},
                {'id':'13','type':'manages','from':'admin','to':'group:domain'},
                {'id':'9','type':'session','from':'alice','to':'admin'},
                {'id':'10','type':'runs','from':'admin','to':'svc','as':'alice'},
                {'id':'11','type':'has_permission','from':'bob','to':'pii','action':'read','effect':'allow'},
                {'id':'12','type':'reaches','from':'outside','to':'web','ports':[443],'protocol':'tcp'},
                {'id':'14','type':'runs','from':'web','to':'svc'}]}


def test_chain_and_proofs():
    e=ThinEngine(ir())
    e.seed([Fact('foothold','web','user'),Fact('acts_as','alice'),Fact('foothold','outside','none')])
    out=e.run()
    assert e.has(Fact('foothold','admin','admin'))
    assert e.has(Fact('has_credential','cred'))
    assert e.has(Fact('controls','group:domain'))
    assert e.has(Fact('data_access','pii','read'))
    assert e.has(Fact('data_access','pii','write'))
    assert e.has(Fact('foothold','web','admin'))
    assert {x.rule for ds in e.proofs.values() for x in ds} >= {f'R{i}' for i in range(1,10)} | {'R11'}
    assert any('R10 candidate' in x for x in out['unresolved_candidates'])


def test_determinism_and_no_duplicate_facts():
    a,b=ThinEngine(ir()),ThinEngine(ir())
    for e in (a,b):e.seed([Fact('foothold','web','user'),Fact('acts_as','alice')])
    assert a.run()==b.run()
    assert len(a.facts)==len(set(a.facts))


def test_denied_or_conditional_permission_not_used():
    data=ir()
    data['relations']=[{'type':'has_permission','from':'alice','to':'pii','action':'read','effect':'deny'},
                       {'type':'has_permission','from':'alice','to':'pii','action':'write','effect':'allow','condition':{'mfa':True}}]
    e=ThinEngine(data);e.seed([Fact('acts_as','alice')]);e.run()
    assert not any(f.kind=='data_access' for f in e.facts)


def test_no_route_means_no_login():
    data=ir();data['relations']=[r for r in data['relations'] if r.get('type')!='reaches']
    e=ThinEngine(data);e.seed([Fact('acts_as','bob'),Fact('foothold','web','user')]);e.run()
    assert not e.has(Fact('foothold','admin','admin'))


def test_uninformed_requires_knowledge():
    e=ThinEngine(ir(),knowledge='uninformed')
    e.seed([Fact('acts_as','bob'),Fact('foothold','web','user')]);e.run()
    assert not e.has(Fact('foothold','admin','admin'))


def test_r10_does_not_assert_compromise():
    e=ThinEngine(ir());e.seed([Fact('foothold','outside','none')]);e.run()
    assert not e.has(Fact('foothold','svc','user'))
    assert e.blocked


def test_alternative_derivations_preserved():
    data=ir();data['relations']=[r for r in data['relations'] if r.get('type')!='manages']
    data['relations'] += [{'type':'manages','from':'admin','to':'web','kind':'backup'},
                          {'type':'manages','from':'admin','to':'web','kind':'deployment'}]
    e=ThinEngine(data);e.seed([Fact('foothold','admin','admin')]);e.run()
    proofs=[p for p in e.proofs[Fact('foothold','web','admin')] if p.rule=='R11']
    assert len(proofs)==2


def test_explicit_deny_overrides_allow():
    data=ir()
    data['relations']=[{'id':'allow','type':'has_permission','from':'alice','to':'pii','action':'read','effect':'allow'},
                       {'id':'deny','type':'has_permission','from':'alice','to':'pii','action':'read','effect':'deny'}]
    e=ThinEngine(data);e.seed([Fact('acts_as','alice')]);e.run()
    assert not e.has(Fact('data_access','pii','read'))


def test_shop_style_group_session_and_exposure():
    data = {
        'groups': [{'id': 'dom-corp', 'kind': 'directory_domain'},
                   {'id': 'nsg-web', 'kind': 'security_group'}],
        'assets': [
            {'id': 'ext-internet', 'type': 'external'},
            {'id': 'web-01', 'type': 'host', 'groups': ['nsg-web']},
            {'id': 'svc-web', 'type': 'service', 'port': 443, 'protocol': 'tcp'},
            {'id': 'dc-01', 'type': 'host', 'role': 'domain_controller', 'groups': ['dom-corp']},
            {'id': 'ws-01', 'type': 'host', 'groups': ['dom-corp']},
            {'id': 'u-staff', 'type': 'identity', 'kind': 'user'},
            {'id': 'u-admin', 'type': 'identity', 'kind': 'user'},
            {'id': 'g-dbadmins', 'type': 'identity', 'kind': 'group'},
            {'id': 'store-db', 'type': 'data_store'},
            {'id': 'data-customer', 'type': 'data'}],
        'relations': [
            {'type':'reaches','from':'ext-internet','to':'group:nsg-web', 'ports':[443], 'protocol':'tcp', 'via':'web-01'},
            {'type':'runs','from':'web-01','to':'svc-web'},
            {'type':'member_of','from':'u-admin','to':'g-dbadmins'},
            {'type':'session','from':'u-staff','to':'ws-01'},
            {'type':'manages','from':'dc-01','to':'group:dom-corp'},
            {'type':'has_permission','from':'g-dbadmins','to':'store-db','action':'admin','effect':'allow'},
            {'type':'contains','from':'store-db','to':'data-customer'}]}
    external = ThinEngine(data)
    external.seed_profile({'id':'external', 'start':['ext-internet']})
    report = external.run()
    assert any('svc-web' in item for item in report['unresolved_candidates'])
    assert not external.has(Fact('foothold', 'svc-web','user'))
    insider = ThinEngine(data)
    insider.seed_profile({'id':'insider','start':['ws-01'],'initial_privilege':'user'})
    insider.run()
    assert insider.has(Fact('acts_as','u-staff'))
    insider.seed([Fact('foothold','dc-01','admin'),Fact('acts_as','u-admin')])
    insider.run()
    assert insider.has(Fact('controls','group:dom-corp'))
    assert insider.has(Fact('acts_as','g-dbadmins'))
    assert not insider.has(Fact('data_access','data-customer','read'))  # encrypted unknown


def test_assumed_reachability_not_confirmed():
    data=ir()
    for r in data['relations']:
        if r.get('type') == 'reaches' and r.get('from') == 'web' and r.get('to') == 'admin':
            r['source'] = 'assumed'
            r['confidence'] = 0.3
    e=ThinEngine(data)
    e.seed([Fact('foothold','web','user'),Fact('acts_as','bob')])
    e.run()
    assert not e.has(Fact('foothold','admin','admin'))
