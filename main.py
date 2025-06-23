import dns.resolver
import asyncio
import socket
import time
import random
import string
import email.utils
import uuid
from collections import defaultdict
from typing import List, Optional, Dict, Tuple, Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr

# ──────────────────────────────────────────────────────────────────────────────
# FASTAPI SETUP WITH CORS
# ──────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="SMTP Email Verifier API",
    description="Batch-verify and find emails by name using SMTP-handshake with optimized catch-all logic.",
    version="2.0.0"
)

origins = [
    "https://bounso.com",
    "http://bounso.com",
    "https://owlsquad.com",
    "http://owlsquad.com",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ──────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────────────────────────────────────────

FROM_ADDRESS_TEMPLATE = "verify@{}"
SOCKET_TIMEOUT = 5.0
CATCHALL_PROBES = 10
CATCHALL_THRESHOLD = 0.8  # fraction accepted to consider catch-all
MAX_CONCURRENT = 5

FREE_MAIL_DOMAINS = {"gmail.com","yahoo.com","outlook.com","hotmail.com","aol.com","icloud.com","protonmail.com","zoho.com"}
DISPOSABLE_DOMAINS = {"mailinator.com","10minutemail.com","yopmail.com","tempmail.com","discard.email","guerrillamail.com"}
ROLE_LOCALS = {"admin","support","info","sales","marketing","billing","postmaster","contact","help","service"}

mx_semaphores: Dict[str, asyncio.Semaphore] = defaultdict(lambda: asyncio.Semaphore(MAX_CONCURRENT))

# ──────────────────────────────────────────────────────────────────────────────
# MODELS
# ──────────────────────────────────────────────────────────────────────────────

class VerifyRequest(BaseModel):
    batch_id: Optional[str] = None
    emails: List[EmailStr]

class PerAddressResult(BaseModel):
    addr: EmailStr; mx: Optional[str] = None; mx_provider: Optional[str] = None
    deliverability: Optional[str] = None; score: Optional[float] = None
    free: Optional[bool] = None; disposable: Optional[bool] = None; role: Optional[bool] = None
    catch_all: Optional[bool] = None; result: Optional[str] = None; verification_time: Optional[float] = None
    method: Optional[str] = None; status: Optional[str] = None; rcpt_code: Optional[int] = None
    rcpt_time: Optional[float] = None; rcpt_msg: Optional[str] = None

class VerifyResponse(BaseModel):
    batch_id: Optional[str]
    results: Dict[EmailStr, PerAddressResult]

class FindEmailByNameRequest(BaseModel):
    batch_id: Optional[str] = None
    names_and_domains: List[Tuple[str,str]]

class FindEmailByNameResult(BaseModel):
    full_name: str; domain: str; found_email: Optional[EmailStr] = None
    verification_details: Optional[PerAddressResult] = None; attempted_patterns: List[str] = []
    status: str

# ──────────────────────────────────────────────────────────────────────────────
# SMTP HELPERS
# ──────────────────────────────────────────────────────────────────────────────

def get_mx_hosts(domain: str) -> List[str]:
    try:
        ans = dns.resolver.resolve(domain,'MX')
        mxs = sorted((r.preference,r.exchange.to_text().rstrip('.')) for r in ans)
        return [mx for _,mx in mxs]
    except:
        return []

async def connect_smtp(mx_host: str):
    return await asyncio.wait_for(asyncio.open_connection(mx_host,25),timeout=SOCKET_TIMEOUT)

async def smtp_cmd(reader,writer,cmd: str)->str:
    writer.write((cmd+"\r\n").encode()); await writer.drain()
    line = await asyncio.wait_for(reader.readuntil(b"\r\n"),timeout=SOCKET_TIMEOUT)
    return line.decode(errors='ignore').strip()

# ──────────────────────────────────────────────────────────────────────────────
# CATCH-ALL DETECTION (SINGLE SESSION MULTI-RCPT)
# ──────────────────────────────────────────────────────────────────────────────

async def detect_catch_all(mx_host: str, domain: str, from_addr: str) -> bool:
    try:
        reader,writer = await connect_smtp(mx_host)
        await smtp_cmd(reader,writer,f"EHLO {domain}")
        await smtp_cmd(reader,writer,f"MAIL FROM:<{from_addr}>")
        accepted=0
        for _ in range(CATCHALL_PROBES):
            rand=''.join(random.choices(string.ascii_lowercase+string.digits,k=8))
            rcpt=f"RCPT TO:<{rand}@{domain}>"
            resp=await smtp_cmd(reader,writer,rcpt)
            code=int(resp[:3]) if resp else 0
            if 200<=code<300: accepted+=1
        await smtp_cmd(reader,writer,"QUIT"); writer.close()
        return (accepted/CATCHALL_PROBES)>=CATCHALL_THRESHOLD
    except:
        return False

# ──────────────────────────────────────────────────────────────────────────────
# SIMPLE VERIFY (RCPT-ONLY)
# ──────────────────────────────────────────────────────────────────────────────

async def verify_address(mx_host: str, domain: str, from_addr: str, addr: str, catch_all: bool) -> PerAddressResult:
    start=time.time()
    result=PerAddressResult(addr=addr,method='simple',mx=mx_host,catch_all=catch_all)
    try:
        reader,writer=await connect_smtp(mx_host)
        await smtp_cmd(reader,writer,f"EHLO {domain}")
        await smtp_cmd(reader,writer,f"MAIL FROM:<{from_addr}>")
        resp=await smtp_cmd(reader,writer,f"RCPT TO:<{addr}>")
        code=int(resp[:3]) if resp else -1
        result.rcpt_code=code; result.rcpt_msg=resp
        if 200<=code<300: result.status='valid'
        elif 500<=code<600: result.status='invalid'
        else: result.status='unknown'
        await smtp_cmd(reader,writer,"QUIT"); writer.close()
    except:
        result.status='connect_failed'
    result.verification_time=time.time()-start
    fill_additional_fields(result,domain,catch_all)
    return result

# ──────────────────────────────────────────────────────────────────────────────
# ADDITIONAL FIELDS & INFERENCE
# ──────────────────────────────────────────────────────────────────────────────

def infer_mx_provider(mx_host:str)->str:
    l=mx_host.lower();
    if 'gmail' in l: return 'Google'
    if any(x in l for x in ('outlook','office365','hotmail','live')): return 'Microsoft'
    return 'Other'

def fill_additional_fields(r:PerAddressResult,domain:str,ca:bool):
    r.mx_provider=infer_mx_provider(r.mx or '')
    r.catch_all=ca
    r.free=domain in FREE_MAIL_DOMAINS
    r.disposable=domain in DISPOSABLE_DOMAINS
    local=r.addr.split('@')[0]; r.role=local in ROLE_LOCALS
    if r.status=='valid': r.result='valid' if not ca else 'risky_catch_all'; r.score=1.0 if not ca else 0.7; r.deliverability='deliverable' if not ca else 'risky'
    elif r.status=='invalid': r.result='invalid'; r.score=0.0; r.deliverability='undeliverable'
    else: r.result='risky'; r.score=0.5; r.deliverability='risky'

# ──────────────────────────────────────────────────────────────────────────────
# MAIN VERIFICATION WORKFLOW
# ──────────────────────────────────────────────────────────────────────────────

async def verify_bulk_async(addresses: List[str]) -> Dict[str,PerAddressResult]:
    by_domain=defaultdict(list); results={}
    for a in addresses:
        d=a.lower().split('@')[-1] if '@' in a else None
        if not d: results[a]=PerAddressResult(addr=a,status='invalid_format'); continue
        by_domain[d].append(a)

    tasks=[]
    for dom,addrs in by_domain.items():
        mxs=get_mx_hosts(dom)
        if not mxs:
            for a in addrs: results[a]=PerAddressResult(addr=a,status='invalid_domain')
            continue
        mx=mxs[0]; frm=FROM_ADDRESS_TEMPLATE.format(dom)
        tasks.append(_verify_domain(dom,addrs,mx,frm))

    for t in await asyncio.gather(*tasks): results.update(t)
    return results

async def _verify_domain(domain,addrs,mx,frm):
    out={}; ca=await detect_catch_all(mx,domain,frm)
    for a in addrs:
        out[a]=await verify_address(mx,domain,frm,a,ca)
    return out

# ──────────────────────────────────────────────────────────────────────────────
# EMAIL PATTERN GENERATION & FIND-BY-NAME
# ──────────────────────────────────────────────────────────────────────────────

def generate_email_patterns(full_name:str,domain:str)->List[str]:
    # [identical to previous implementation]
    cleaned=full_name.lower().replace("'","").replace("-","")
    parts=cleaned.split(); first=parts[0] if parts else ''; last=parts[-1] if len(parts)>1 else ''
    mids=parts[1][0] if len(parts)>2 else ''
    pats=[]
    if first and last:
        pats+=[f"{first}.{last}@{domain}",f"{first}{last}@{domain}",f"{first[0]}{last}@{domain}"]
    if first: pats.append(f"{first}@{domain}")
    if last: pats.append(f"{last}@{domain}")
    seen=set();up=[]
    for p in pats:
        if p not in seen: up.append(p); seen.add(p)
    return up

@app.post("/find_email_by_name",response_model=List[FindEmailByNameResult])
async def find_by_name(req:FindEmailByNameRequest):
    if len(req.names_and_domains)>10: raise HTTPException(400,"Max 10")
    res=[]
    for name,dom in req.names_and_domains:
        patterns=generate_email_patterns(name,dom)
        found=None;detail=None
        mxs=get_mx_hosts(dom)
        if not mxs: res.append(FindEmailByNameResult(full_name=name,domain=dom,status='not_found',attempted_patterns=patterns)); continue
        mx=mxs[0];frm=FROM_ADDRESS_TEMPLATE.format(dom)
        ca=await detect_catch_all(mx,dom,frm)
        for p in patterns:
            r=await verify_address(mx,dom,frm,p,ca)
            if r.result in ('valid','risky_catch_all'):
                found=p; detail=r; break
        status='found' if found else 'not_found'
        res.append(FindEmailByNameResult(full_name=name,domain=dom,found_email=found,verification_details=detail,attempted_patterns=patterns,status=status))
    return res

@app.post("/verify",response_model=VerifyResponse)
async def batch_verify(req:VerifyRequest):
    if len(req.emails)>200: raise HTTPException(400,"Max 200")
    raw=await verify_bulk_async(req.emails)
    final={e:raw.get(e,PerAddressResult(addr=e,status='unknown')) for e in req.emails}
    return VerifyResponse(batch_id=req.batch_id,results=final)
