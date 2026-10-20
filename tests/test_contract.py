import copy
import hashlib
import json
from pathlib import Path
import re
import pytest
from gltest.direct import create_address

ROOT=Path(__file__).parents[1];META=json.loads((ROOT/'fixtures/source.json').read_text());BODY=(ROOT/'fixtures/input.json').read_bytes();URL=META['test_url']
def sha(body):return hashlib.sha256(body).hexdigest()
def deploy(vm,build):
    vm.warp('2026-10-21T00:00:00Z');c=build(str(ROOT/'erasure_stripe_witness.py'),sdk_version='v0.2.12');assert hasattr(c,'register'),'ErasureStripeWitness API not implemented';return c
def mock(vm,body=BODY,status=200):vm.clear_mocks();vm.mock_web(re.escape(URL),{'status':status,'body':body})
def register(vm,c,body=BODY,ident='stripe'):
    mock(vm,body);c.register(ident,URL,sha(body))
def body(data):return json.dumps(data).encode()

def test_literal_coefficients_all_redundancy_and_active_evaluation(direct_vm,direct_deploy):
    c=deploy(direct_vm,direct_deploy);register(direct_vm,c);cert=c.certify('stripe',0);r=c.get_stripe('stripe')['result']
    assert r['field']==257 and r['k']==2 and r['columns']==2 and r['basis_x']==[1,2]
    assert r['status']=='CONSISTENT' and r['candidate_coefficients']==[[3,5],[7,2]] and r['first_mismatch'] is None
    assert r['data_sha256']==sha(b'[[3,5],[7,2]]') and direct_vm.run_validator() is True
    assert c.verify_shard('stripe',2,cert,0,'[3,7]') is False
    c.activate('stripe',1,cert)
    for x,values in [(0,[3,7]),(200,[232,150]),(256,[255,5])]:assert c.verify_shard('stripe',2,cert,x,json.dumps(values)) is True
    assert c.verify_shard('stripe',2,cert,200,'[232,151]') is False

def test_finite_field_wrap_and_degree_two_inverse(direct_vm,direct_deploy):
    c=deploy(direct_vm,direct_deploy);data={'version':1,'k':3,'shards':[{'x':4,'values':[27]},{'x':1,'values':[0]},{'x':3,'values':[14]},{'x':2,'values':[5]}]}
    register(direct_vm,c,body(data));cert=c.certify('stripe',0);r=c.get_stripe('stripe')['result']
    assert r['candidate_coefficients']==[[256,256,2]] and r['status']=='CONSISTENT'
    c.activate('stripe',1,cert);assert c.verify_shard('stripe',2,cert,256,'[2]') is True

def test_all_redundant_points_and_first_mismatch_cannot_activate(direct_vm,direct_deploy):
    c=deploy(direct_vm,direct_deploy);data=json.loads(BODY);data['shards'][2]['values'][1]=16;register(direct_vm,c,body(data));cert=c.certify('stripe',0);r=c.get_stripe('stripe')['result']
    assert r['status']=='INCONSISTENT' and r['first_mismatch']=={'x':4,'column':1,'expected':15,'observed':16} and r['data_sha256'] is None
    assert direct_vm.run_validator() is True
    with direct_vm.expect_revert('consistent'):c.activate('stripe',1,cert)
    assert c.get_stripe('stripe')['status']=='CERTIFIED'

def test_negative_certificate_forged_mismatch_is_not_accepted(direct_vm,direct_deploy):
    c=deploy(direct_vm,direct_deploy);data=json.loads(BODY);data['shards'][2]['values'][1]=16;register(direct_vm,c,body(data));c.certify('stripe',0);packet=copy.deepcopy(c.get_stripe('stripe')['attestation'])
    packet['result']['first_mismatch']['x']=3
    assert direct_vm.run_validator(leader_result=packet) is False

def test_source_permutation_has_same_canonical_result(direct_vm,direct_deploy):
    c=deploy(direct_vm,direct_deploy);register(direct_vm,c);c.certify('stripe',0);expected=c.get_stripe('stripe')['result'];data=json.loads(BODY);data['shards'].reverse()
    register(direct_vm,c,body(data),'other');c.certify('other',0);assert c.get_stripe('other')['result']==expected

def test_valid_max_dimensions_and_exact_body_cap(direct_vm,direct_deploy):
    c=deploy(direct_vm,direct_deploy);data={'version':1,'k':8,'shards':[{'x':x,'values':[5]*16} for x in range(1,13)]};b=body(data);b+=b' '*(16384-len(b));register(direct_vm,c,b);c.certify('stripe',0);r=c.get_stripe('stripe')['result']
    assert r['status']=='CONSISTENT' and r['basis_x']==list(range(1,9)) and r['candidate_coefficients']==[[5,0,0,0,0,0,0,0]]*16

@pytest.mark.parametrize('kind',['coefficient','status','data-hash','basis','binding'])
def test_full_shaped_forgery_is_rejected_by_independent_validator(direct_vm,direct_deploy,kind):
    c=deploy(direct_vm,direct_deploy);register(direct_vm,c);c.certify('stripe',0);packet=copy.deepcopy(c.get_stripe('stripe')['attestation'])
    if kind=='coefficient':packet['result']['candidate_coefficients'][0][0]=4
    elif kind=='status':packet['result']['status']='INCONSISTENT'
    elif kind=='data-hash':packet['result']['data_sha256']='00'*32
    elif kind=='basis':packet['result']['basis_x']=[2,3]
    else:packet['binding']['stripe_id']='other'
    assert direct_vm.run_validator(leader_result=packet) is False

def test_validator_refetch_and_leader_failure_leave_registration(direct_vm,direct_deploy):
    c=deploy(direct_vm,direct_deploy);register(direct_vm,c);c.certify('stripe',0);mock(direct_vm,BODY+b' ');assert direct_vm.run_validator() is False
    register(direct_vm,c,ident='offline');mock(direct_vm,b'',503)
    with direct_vm.expect_revert('SOURCE'):c.certify('offline',0)
    assert c.get_stripe('offline')['revision']==0 and c.get_stripe('offline')['certificate_id']==''

@pytest.mark.parametrize('kind',['bool-version','bool-k','small-k','large-k','no-redundancy','too-many','zero-x','large-x','duplicate-x','bool-x','zero-width','wide','unequal-width','bool-symbol','negative-symbol','large-symbol','nan','duplicate-key','extra','invalid-utf8','body-over'])
def test_strict_stripe_schema_and_resource_limits(direct_vm,direct_deploy,kind):
    c=deploy(direct_vm,direct_deploy);data=json.loads(BODY)
    if kind=='bool-version':data['version']=True
    elif kind=='bool-k':data['k']=True
    elif kind=='small-k':data['k']=1
    elif kind=='large-k':data['k']=9
    elif kind=='no-redundancy':data['shards']=data['shards'][:2]
    elif kind=='too-many':data['shards']=[{'x':x,'values':[5]} for x in range(1,14)]
    elif kind=='zero-x':data['shards'][0]['x']=0
    elif kind=='large-x':data['shards'][0]['x']=257
    elif kind=='duplicate-x':data['shards'][0]['x']=1
    elif kind=='bool-x':data['shards'][0]['x']=True
    elif kind=='zero-width':
        for s in data['shards']:s['values']=[]
    elif kind=='wide':
        for s in data['shards']:s['values']=[5]*17
    elif kind=='unequal-width':data['shards'][0]['values']=[5]
    elif kind=='bool-symbol':data['shards'][0]['values'][0]=True
    elif kind=='negative-symbol':data['shards'][0]['values'][0]=-1
    elif kind=='large-symbol':data['shards'][0]['values'][0]=257
    elif kind=='nan':data['shards'][0]['values'][0]=float('nan')
    elif kind=='extra':data['shards'][0]['claimed_valid']=True
    b=b'{"version":1,"k":2,"k":2,"shards":[]}' if kind=='duplicate-key' else (b'\xff' if kind=='invalid-utf8' else body(data))
    if kind=='body-over':b=b+b' '*16384
    register(direct_vm,c,b)
    with direct_vm.expect_revert():c.certify('stripe',0)
    assert c.get_stripe('stripe')['certificate_id']==''

@pytest.mark.parametrize('x,values',[(True,'[3,7]'),(-1,'[3,7]'),(257,'[3,7]'),(0,'[true,7]'),(0,'[3]'),(0,'[3,257]'),(0,'[NaN,7]'),(0,'{"0":3,"1":7}')])
def test_active_evaluation_strict_shape(direct_vm,direct_deploy,x,values):
    c=deploy(direct_vm,direct_deploy);register(direct_vm,c);cert=c.certify('stripe',0);c.activate('stripe',1,cert);assert c.verify_shard('stripe',2,cert,x,values) is False

def test_owner_cas_exact_receipt_cross_record_and_terminal_history(direct_vm,direct_deploy):
    c=deploy(direct_vm,direct_deploy);other=create_address('other')
    with direct_vm.prank(other):
        with direct_vm.expect_revert('owner only'):register(direct_vm,c)
    register(direct_vm,c)
    with direct_vm.prank(other):cert=c.certify('stripe',0)
    with direct_vm.prank(other):
        with direct_vm.expect_revert('owner only'):c.activate('stripe',1,cert)
        with direct_vm.expect_revert('owner only'):c.revoke('stripe',1,'withdraw')
    with direct_vm.expect_revert('revision'):c.activate('stripe',True,cert)
    with direct_vm.expect_revert('revision'):c.activate('stripe',0,cert)
    register(direct_vm,c,ident='other');othercert=c.certify('other',0);assert othercert!=cert
    with direct_vm.expect_revert('certificate'):c.activate('stripe',1,othercert)
    c.activate('stripe',1,cert);direct_vm.clear_mocks();c.revoke('stripe',2,'Withdraw codeword.')
    assert c.verify_shard('stripe',3,cert,0,'[3,7]') is False and c.is_active('stripe',cert,2) is False
    assert [e['status'] for e in c.get_stripe('stripe')['history']]==['REGISTERED','CERTIFIED','ACTIVE','REVOKED']
    with direct_vm.expect_revert():c.certify('stripe',3)
    with direct_vm.expect_revert('already used'):register(direct_vm,c)

def test_pinned_namespace_and_lifetime_capacity(direct_vm,direct_deploy):
    c=deploy(direct_vm,direct_deploy)
    for url in [URL.replace('/public-demo/','/./'),URL.replace('/public-demo/','/../'),URL.replace('0'*40,'main'),URL+'?x=1']:
        with direct_vm.expect_revert('commit-pinned'):c.register('bad',url,META['sha256'])
    for i in range(8):c.register('s'+str(i),URL,META['sha256'])
    c.revoke('s0',0,'Withdraw unused stripe.')
    with direct_vm.expect_revert('capacity'):c.register('overflow',URL,META['sha256'])
