import dns.resolver
import socket
import ssl
import time
import random
import string
import email.utils
import uuid
from collections import defaultdict

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from typing import List, Optional, Dict, Tuple

# FASTAPI SETUP WITH CORS
app = FastAPI(
    title="SMTP Email Verifier API",
    description="Batch‐verify email addresses using SMTP‐handshake + timing for catch‐all domains, with extended metadata and CORS enabled for bounso.com.",
    version="1.2.0"
)
origins = ["https://bounso.com", "http://bounso.com"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# CONFIGURATION
FROM_ADDRESS_TEMPLATE = "verify@{}"
SOCKET_TIMEOUT = 5.0
NUM_CALIBRATE = 2
RCPT_RETRIES = 1
TIMING_CUSHION = 0.05
FREE_MAIL_DOMAINS = {"gmail.com","yahoo.com","outlook.com","hotmail.com","aol.com","icloud.com","protonmail.com","zoho.com"}
DISPOSABLE_DOMAINS = {"mailinator.com","10minutemail.com","yopmail.com","tempmail.com","discard.email","guerrillamail.com"}
ROLE_LOCALS = {"admin","administrator","support","info","sales","marketing","billing","webmaster","postmaster","contact","help","service"}

# MODELS
class VerifyRequest(BaseModel):
    batch_id: Optional[str]
    emails: List[EmailStr]

class PerAddressResult(BaseModel):
    addr: EmailStr
    mx: Optional[str]
    mx_provider: Optional[str]
    deliverability: Optional[str]
    score: Optional[float]
    free: Optional[bool]
    disposable: Optional[bool]
    role: Optional[bool]
    catch_all: Optional[bool]
    result: Optional[str]
    verification_time: Optional[float]
    method: Optional[str]
    status: Optional[str]
    rcpt_code: Optional[int]
    rcpt_time: Optional[float]
    rcpt_msg: Optional[str]
    data_code: Optional[int]
    data_msg: Optional[str]

class VerifyResponse(BaseModel):
    batch_id: Optional[str]
    results: Dict[EmailStr, PerAddressResult]

# SMTP + DNS HELPERS

def get_mx_hosts(domain: str) -> List[str]:
    try:
        answers = dns.resolver.resolve(domain, "MX")
        mx_list = sorted(((r.preference, r.exchange.to_text().rstrip(".")) for r in answers), key=lambda x: x[0])
        return [host for _, host in mx_list]
    except:
        try: dns.resolver.resolve(domain, "A"); return [domain]
        except: pass
        try: dns.resolver.resolve(domain, "AAAA"); return [domain]
        except: pass
    return []

def recv_line(sock: socket.socket) -> str:
    data = b""
    while True:
        ch = sock.recv(1)
        if not ch: break
        data += ch
        if data.endswith(b"\r\n"): break
    return data.decode(errors="ignore").rstrip("\r\n")

def send_line(sock: socket.socket, line: str):
    sock.sendall((line + "\r\n").encode())

def parse_code(line: str) -> int:
    try: return int(line[:3])
    except: return -1

def connect_smtp(mx_host: str) -> socket.socket:
    sock = socket.create_connection((mx_host, 25), timeout=SOCKET_TIMEOUT)
    sock.settimeout(SOCKET_TIMEOUT)
    return sock

def smtp_ehlo(sock: socket.socket, domain: str):
    send_line(sock, f"EHLO {domain}")
    while True:
        line = recv_line(sock)
        if not line.startswith("250-"): break

def smtp_mail_from(sock: socket.socket, from_addr: str) -> int:
    send_line(sock, f"MAIL FROM:<{from_addr}>")
    return parse_code(recv_line(sock))

def smtp_rcpt_to(sock: socket.socket, to_addr: str) -> Tuple[int,float,str]:
    start = time.time()
    send_line(sock, f"RCPT TO:<{to_addr}>")
    resp = recv_line(sock)
    return parse_code(resp), time.time()-start, resp

def smtp_quit(sock: socket.socket):
    try: send_line(sock, "QUIT"); recv_line(sock)
    except: pass
    finally: sock.close()

# CATCH-ALL DETECTION

def detect_catch_all(mx_host: str, domain: str, from_addr: str) -> bool:
    for _ in range(NUM_CALIBRATE):
        rand = ''.join(random.choices(string.ascii_lowercase+string.digits,k=10))
        test_addr = f"{rand}@{domain}"
        try:
            sock = connect_smtp(mx_host); recv_line(sock)
            smtp_ehlo(sock, domain)
            if smtp_mail_from(sock, from_addr) != 250:
                smtp_quit(sock)
                return False
            for attempt in range(RCPT_RETRIES+1):
                code, _, _ = smtp_rcpt_to(sock, test_addr)
                if 500 <= code < 600:
                    smtp_quit(sock)
                    return False
                if 200 <= code < 300:
                    break
                if 400 <= code < 500:
                    time.sleep(0.2*(attempt+1))
                    continue
                smtp_quit(sock)
                return False
            smtp_quit(sock)
        except:
            return False
    return True

# TIMING-BASED VERIFY

def calibrate_fake_timing(mx_host: str, domain: str, from_addr: str) -> float:
    times = []
    for _ in range(NUM_CALIBRATE):
        rand = ''.join(random.choices(string.ascii_lowercase+string.digits,k=10))
        addr = f"{rand}@{domain}"
        try:
            sock = connect_smtp(mx_host); recv_line(sock)
            smtp_ehlo(sock, domain); smtp_mail_from(sock, from_addr)
            code, elapsed, _ = smtp_rcpt_to(sock, addr)
            if 200 <= code < 300:
                times.append(elapsed)
            smtp_quit(sock)
        except:
            pass
    return sum(times)/len(times) if times else 0.0

# SINGLE-ADDRESS VERIFY

def verify_with_timing(mx_host, domain, from_addr, target, avg):
    start = time.time()
    res = PerAddressResult(addr=target, mx=mx_host, method="timing")
    try:
        sock = connect_smtp(mx_host); recv_line(sock)
        smtp_ehlo(sock, domain); smtp_mail_from(sock, from_addr)
        c, rt, msg = smtp_rcpt_to(sock, target)
        res.rcpt_code, res.rcpt_time, res.rcpt_msg = c, rt, msg
        if 500 <= c < 600:
            res.status = "invalid"
        elif 400 <= c < 500:
            res.status = "unknown_temp"
        else:
            res.status = "valid" if rt > avg + TIMING_CUSHION else "invalid"
        smtp_quit(sock)
    except:
        res.status = "connect_failed"
    fill_additional_fields(res, domain, True)
    res.verification_time = time.time() - start
    return res


def verify_simple(mx_host, domain, from_addr, target):
    start = time.time()
    res = PerAddressResult(addr=target, mx=mx_host, method="simple")
    try:
        sock = connect_smtp(mx_host); recv_line(sock)
        smtp_ehlo(sock, domain); smtp_mail_from(sock, from_addr)
        c, rt, msg = smtp_rcpt_to(sock, target)
        res.rcpt_code, res.rcpt_time, res.rcpt_msg = c, rt, msg
        if 500 <= c < 600:
            res.status = "invalid"
            smtp_quit(sock)
        elif 400 <= c < 500:
            res.status = "unknown_temp"
            smtp_quit(sock)
        else:
            send_line(sock, "DATA")
            d = recv_line(sock)
            res.data_code = parse_code(d)
            res.data_msg = d
            if d.startswith("354"):
                send_line(sock, f"Date: {email.utils.formatdate(localtime=False)}")
                send_line(sock, f"From: <{from_addr}>")
                send_line(sock, f"To: <{target}>")
                send_line(sock, "Subject: Test")
                send_line(sock, f"Message-ID:<{uuid.uuid4().hex}@{domain}>")
                send_line(sock, "")
                send_line(sock, "This is a test.")
                send_line(sock, ".")
                d2 = recv_line(sock)
                res.data_code = parse_code(d2)
                res.data_msg = d2
                res.status = "valid" if 200 <= res.data_code < 300 else "invalid"
            else:
                res.status = "unknown"
        smtp_quit(sock)
    except:
        res.status = "connect_failed"
    fill_additional_fields(res, domain, False)
    res.verification_time = time.time() - start
    return res

# ADDITIONAL FIELDS

def infer_mx_provider(mx):
    m = (mx or "").lower()
    if "google" in m or m.endswith("gmail.com"): return "Google"
    if any(x in m for x in ["outlook","office365","hotmail","live"]): return "Microsoft"
    return "Other"

def infer_free(d): return d.lower() in FREE_MAIL_DOMAINS

def infer_disposable(d): return d.lower() in DISPOSABLE_DOMAINS

def infer_role(local): return local.lower() in ROLE_LOCALS

def infer_deliverability(status): return {"valid":"deliverable","invalid":"undeliverable"}.get(status, "risky")

def infer_score(status): return {"valid":1.0,"invalid":0.0}.get(status, 0.5)

def fill_additional_fields(r, domain, ca):
    r.mx_provider = infer_mx_provider(r.mx)
    r.catch_all = ca
    r.deliverability = infer_deliverability(r.status or "")
    r.score = infer_score(r.status or "")
    local = r.addr.split("@",1)[0]
    r.free = infer_free(domain)
    r.disposable = infer_disposable(domain)
    r.role = infer_role(local)
    r.result = r.status if r.status in ("valid","invalid") else "risky"

# BULK VERIFY

def verify_bulk(addrs: List[str]) -> Dict[str, PerAddressResult]:
    domains = defaultdict(list)
    for a in addrs:
        if "@" not in a:
            domains[None].append(a)
        else:
            local, dom = a.rsplit("@",1)
            domains[dom].append(a)

    out: Dict[str, PerAddressResult] = {}
    for dom, alist in domains.items():
        if dom is None:
            for a in alist:
                r = PerAddressResult(addr=a)
                r.status = "invalid_format"
                r.mx = None
                fill_additional_fields(r, dom, False)
                r.verification_time = 0.0
                out[a] = r
            continue

        mxs = get_mx_hosts(dom)
        if not mxs:
            for a in alist:
                r = PerAddressResult(addr=a)
                r.status = "invalid_domain"
                r.mx = None
                fill_additional_fields(r, dom, False)
                r.verification_time = 0.0
                out[a] = r
            continue

        mx = mxs[0]
        from_addr = FROM_ADDRESS_TEMPLATE.format(dom)
        is_catch = detect_catch_all(mx, dom, from_addr)

        if not is_catch:
            for a in alist:
                r = verify_simple(mx, dom, from_addr, a)
                out[a] = r
        else:
            avg = calibrate_fake_timing(mx, dom, from_addr)
            for a in alist:
                if avg <= 0:
                    r = PerAddressResult(addr=a)
                    r.method = "timing"
                    r.status = "unknown_catchall"
                    r.mx = mx
                    fill_additional_fields(r, dom, True)
                    r.verification_time = 0.0
                    out[a] = r
                else:
                    r = verify_with_timing(mx, dom, from_addr, a, avg)
                    out[a] = r
    return out

# API ROUTE
@app.post("/verify", response_model=VerifyResponse)
def batch_verify(req: VerifyRequest):
    if len(req.emails) > 200:
        raise HTTPException(status_code=400, detail="Max 200 emails")
    res = verify_bulk([str(e) for e in req.emails])
    return VerifyResponse(batch_id=req.batch_id, results=res)
