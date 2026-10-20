# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
from genlayer import *
import hashlib
import json
import re
from datetime import datetime, timezone


def _require(ok: bool,message: str) -> None:
    if not ok:raise gl.vm.UserError('[EXPECTED] '+message)


def _canon(value) -> str:
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)


def _hash(value) -> str:
    return hashlib.sha256(_canon(value).encode()).hexdigest()


def _now() -> int:
    t=datetime.fromisoformat(gl.message_raw['datetime'].replace('Z','+00:00'))
    if t.tzinfo is None:t=t.replace(tzinfo=timezone.utc)
    d=t.astimezone(timezone.utc)-datetime(1970,1,1,tzinfo=timezone.utc)
    return d.days*86400+d.seconds


def _id(value: str) -> None:
    _require(isinstance(value,str) and re.fullmatch(r'[A-Za-z0-9_-]{1,32}',value) is not None,'invalid ASCII identifier')


def _digest(value) -> bool:
    return isinstance(value,str) and re.fullmatch(r'[0-9a-f]{64}',value) is not None


def _path(value) -> bool:
    return isinstance(value,str) and 1<=len(value)<=192 and re.fullmatch(r'[A-Za-z0-9_.~/-]+',value) is not None and all(part not in ('','.','..') for part in value.split('/'))


def _source(url: str,digest: str) -> str:
    m=re.fullmatch(r'https://raw\.githubusercontent\.com/([A-Za-z0-9-]{1,39})/([A-Za-z0-9_.-]{1,100})/([0-9a-f]{40})/([A-Za-z0-9_.~/-]+)',url) if isinstance(url,str) and len(url)<=512 else None
    _require(m is not None,'commit-pinned public source required')
    owner,repo,commit,path=m.groups()
    _require(owner[0].isalnum() and owner[-1].isalnum() and '--' not in owner and repo not in ('.','..') and _path(path),'commit-pinned public source requires safe namespace/path segments')
    _require(_digest(digest),'invalid SHA256')
    return 'https://raw.githubusercontent.com/'+owner+'/'+repo+'/'+commit+'/'


def _pairs(pairs: list) -> dict:
    result={}
    for key,value in pairs:
        _require(key not in result,'duplicate JSON key');result[key]=value
    return result


def _constant(value: str):
    raise gl.vm.UserError('[SOURCE] non-finite JSON literal')


def _json(text: str):
    try:return json.loads(text,object_pairs_hook=_pairs,parse_constant=_constant)
    except (ValueError,UnicodeError,RecursionError):raise gl.vm.UserError('[SOURCE] invalid JSON')


def _bytes(url: str,digest: str,limit: int) -> bytes:
    response=gl.nondet.web.get(url,headers={'Accept':'application/octet-stream'})
    if response.status!=200 or response.body is None or len(response.body)>limit:
        raise gl.vm.UserError('[SOURCE] unavailable or oversized bytes')
    if hashlib.sha256(response.body).hexdigest()!=digest:raise gl.vm.UserError('[SOURCE] byte digest mismatch')
    return response.body




def _stripe(url: str,digest: str) -> tuple:
    raw=_bytes(url,digest,16384);_require(len(raw)>0,'empty stripe document')
    try:data=_json(raw.decode('utf-8'))
    except UnicodeError:raise gl.vm.UserError('[SOURCE] invalid UTF8 stripe')
    _require(isinstance(data,dict) and set(data)=={'version','k','shards'} and type(data['version']) is int and data['version']==1,'stripe version/fields')
    k=data['k'];shards=data['shards']
    _require(type(k) is int and 2<=k<=8,'threshold must be integer 2..8')
    _require(isinstance(shards,list) and k+1<=len(shards)<=12,'at least one redundant shard and max12 required')
    seen=set();width=0
    for shard in shards:
        _require(isinstance(shard,dict) and set(shard)=={'x','values'},'shard fields')
        x=shard['x'];values=shard['values']
        _require(type(x) is int and 1<=x<=256 and x not in seen,'unique nonzero field x required');seen.add(x)
        _require(isinstance(values,list) and 1<=len(values)<=16 and all(type(v) is int and 0<=v<=256 for v in values),'bounded integer field symbols required')
        if width==0:width=len(values)
        _require(len(values)==width,'shard vector widths must agree')
    return k,sorted(shards,key=lambda shard:shard['x'])


def _linear(poly: list,root: int) -> list:
    result=[0]*(len(poly)+1)
    for i,coefficient in enumerate(poly):
        result[i]=(result[i]-root*coefficient)%257
        result[i+1]=(result[i+1]+coefficient)%257
    return result


def _evaluate(coefficients: list,x: int) -> int:
    value=0
    for coefficient in reversed(coefficients):value=(value*x+coefficient)%257
    return value


def _decode(k: int,shards: list) -> dict:
    basis=shards[:k];width=len(basis[0]['values']);matrix=[[0]*k for _ in range(width)]
    for j,point in enumerate(basis):
        polynomial=[1];denominator=1
        for other_index,other in enumerate(basis):
            if other_index!=j:
                polynomial=_linear(polynomial,other['x'])
                denominator=(denominator*(point['x']-other['x']))%257
        _require(denominator!=0,'internal distinct-point denominator')
        inverse=pow(denominator,255,257)
        for column,y in enumerate(point['values']):
            factor=(y*inverse)%257
            for degree,coefficient in enumerate(polynomial):matrix[column][degree]=(matrix[column][degree]+factor*coefficient)%257
    mismatch=None
    # Examine every actual symbol, not just the k interpolation basis points.
    for point in shards:
        for column,observed in enumerate(point['values']):
            expected=_evaluate(matrix[column],point['x'])
            if expected!=observed and mismatch is None:mismatch={'x':point['x'],'column':column,'expected':expected,'observed':observed}
    return {'field':257,'k':k,'columns':width,'basis_x':[p['x'] for p in basis],'candidate_coefficients':matrix,'status':'CONSISTENT' if mismatch is None else 'INCONSISTENT','first_mismatch':mismatch,'data_sha256':_hash(matrix) if mismatch is None else None}


def _capture(url: str,digest: str,binding: dict) -> dict:
    def leader() -> dict:
        k,shards=_stripe(url,digest)
        return {'binding':binding,'shards':shards,'result':_decode(k,shards)}
    def validator(proposed: gl.vm.Result) -> bool:
        if not isinstance(proposed,gl.vm.Return):return False
        try:
            # Fresh bytes, complete schema and every vector, independent interpolation and all redundancy checks.
            return _canon(leader())==_canon(proposed.calldata)
        except Exception:return False
    return gl.vm.run_nondet_unsafe(leader,validator)


class ErasureStripeWitness(gl.Contract):
    owner: Address
    stripes: TreeMap[str,str]
    registrations: u256

    def __init__(self):self.owner=gl.message.sender_address

    def _owner(self) -> None:_require(gl.message.sender_address==self.owner,'owner only')

    def _load(self,stripe_id: str) -> dict:
        _require(stripe_id in self.stripes,'unknown stripe');return json.loads(self.stripes[stripe_id])

    def _cas(self,d: dict,revision: int) -> None:_require(type(revision) is int and revision==d['revision'],'stale revision')

    def _save(self,stripe_id: str,d: dict) -> None:self.stripes[stripe_id]=_canon(d)

    def _phase(self,d: dict,status: str) -> None:
        _require(len(d['history'])<4,'history capacity');d['status']=status;d['revision']+=1;d['history'].append({'status':status,'revision':d['revision'],'at':_now()})

    @gl.public.write
    def register(self,stripe_id: str,source_url: str,source_sha256: str) -> None:
        self._owner();_id(stripe_id);_source(source_url,source_sha256)
        _require(stripe_id not in self.stripes,'stripe ID already used');_require(int(self.registrations)<8,'registration capacity')
        d={'stripe_id':stripe_id,'owner':self.owner.as_hex.lower(),'source_url':source_url,'source_sha256':source_sha256,'registered_at':_now(),'status':'REGISTERED','revision':0,'certificate_id':'','result':None,'attestation':None,'reason':'','history':[{'status':'REGISTERED','revision':0,'at':_now()}]}
        self._save(stripe_id,d);self.registrations=u256(int(self.registrations)+1)

    @gl.public.write
    def certify(self,stripe_id: str,expected_revision: int) -> str:
        d=self._load(stripe_id);self._cas(d,expected_revision);_require(d['status']=='REGISTERED','stripe not registered for certification')
        binding={'protocol':'ErasureStripeWitness-v1','chain_id':int(gl.message.chain_id),'contract':gl.message.contract_address.as_hex.lower(),'owner':d['owner'],'stripe_id':stripe_id,'source_url':d['source_url'],'source_sha256':d['source_sha256'],'registered_at':d['registered_at'],'expected_revision':expected_revision,'certifier':gl.message.sender_address.as_hex.lower(),'certified_at':_now()}
        packet=_capture(d['source_url'],d['source_sha256'],binding);d['attestation']=packet;d['result']=packet['result'];d['certificate_id']=_hash(['ErasureStripeWitness-certificate-v1',packet]);self._phase(d,'CERTIFIED');self._save(stripe_id,d);return d['certificate_id']

    @gl.public.write
    def activate(self,stripe_id: str,expected_revision: int,certificate_id: str) -> None:
        self._owner();d=self._load(stripe_id);self._cas(d,expected_revision);_require(d['status']=='CERTIFIED','certificate not ready');_require(isinstance(certificate_id,str) and certificate_id==d['certificate_id'],'certificate mismatch');_require(d['result']['status']=='CONSISTENT','consistent stripe required');self._phase(d,'ACTIVE');self._save(stripe_id,d)

    @gl.public.write
    def revoke(self,stripe_id: str,expected_revision: int,reason: str) -> None:
        self._owner();d=self._load(stripe_id);self._cas(d,expected_revision);_require(d['status']!='REVOKED','stripe already revoked');_require(isinstance(reason,str) and 1<=len(reason)<=200 and reason==reason.strip(),'revocation reason required');d['reason']=reason;self._phase(d,'REVOKED');self._save(stripe_id,d)

    @gl.public.view
    def get_stripe(self,stripe_id: str) -> dict:return self._load(stripe_id)

    @gl.public.view
    def is_active(self,stripe_id: str,certificate_id: str,expected_revision: int) -> bool:
        if stripe_id not in self.stripes:return False
        d=self._load(stripe_id);return d['status']=='ACTIVE' and isinstance(certificate_id,str) and certificate_id==d['certificate_id'] and type(expected_revision) is int and expected_revision==d['revision']

    @gl.public.view
    def verify_shard(self,stripe_id: str,expected_revision: int,certificate_id: str,x: int,values_json: str) -> bool:
        if not self.is_active(stripe_id,certificate_id,expected_revision) or type(x) is not int or not 0<=x<=256 or not isinstance(values_json,str) or len(values_json)>512:return False
        try:
            values=_json(values_json);result=self._load(stripe_id)['result']
            if not isinstance(values,list) or len(values)!=result['columns'] or not all(type(v) is int and 0<=v<=256 for v in values):return False
            return all(_evaluate(coefficients,x)==values[column] for column,coefficients in enumerate(result['candidate_coefficients']))
        except Exception:return False

    @gl.public.view
    def get_configuration(self) -> dict:
        return {'protocol':'ErasureStripeWitness-v1','owner':self.owner.as_hex.lower(),'registrations':int(self.registrations),'max_stripes':8,'field':257,'min_k':2,'max_k':8,'max_shards':12,'max_columns':16,'max_source_bytes':16384,'max_history':4,'claim':'consistency of declared public polynomial-coded symbols, not error correction or secrecy'}
