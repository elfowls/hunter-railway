import dns.resolver
import socket
import time
import random
import string
import email.utils
import uuid
from collections import defaultdict

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from typing import List, Optional, Dict

# ──────────────────────────────────────────────────────────────────────────────
# FASTAPI SETUP WITH CORS
# ──────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="SMTP Email Verifier API",
    description=(
        "Batch-verify email addresses using SMTP-handshake + timing for catch-all domains, "
        "with extended metadata and CORS enabled for bounso.com and owlsquad.com."
    ),
    version="1.2.0"
)

# ──────────────────────────────────────────────────────────────────────────────
# ADD CORS MIDDLEWARE
# ──────────────────────────────────────────────────────────────────────────────

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
NUM_CALIBRATE = 3  # use 3 fakes for catch-all detection
TIMING_CUSHION = 0.05

# ──────────────────────────────────────────────────────────────────────────────
# MODELS
# ──────────────────────────────────────────────────────────────────────────────

class PatternVerifyRequest(BaseModel):
    full_name: str
    domain: str

class PerAddressResult(BaseModel):
    addr: EmailStr
    mx: Optional[str] = None
    method: Optional[str] = None
    status: Optional[str] = None
    rcpt_time: Optional[float] = None
    score: Optional[float] = None
    catch_all: Optional[bool] = None

class PatternVerifyResponse(BaseModel):
    chosen: PerAddressResult
    all_results: Dict[str, PerAddressResult]

# ──────────────────────────────────────────────────────────────────────────────
# PATTERN GENERATION
# ──────────────────────────────────────────────────────────────────────────────

def generate_patterns(full_name: str, domain: str) -> List[str]:
    parts = full_name.strip().lower().split()
    first = parts[0]
    last = parts[-1]
    f = first[0]
    l = last[0]
    patterns = [
        f"{first}@{domain}",
        f"{last}@{domain}",
        f"{first}.{last}@{domain}",
        f"{f}{l}@{domain}",
        f"{f}.{l}@{domain}",
        f"{first[:2]}{last}@{domain}",
        f"{f}.{last}@{domain}",
        f"{first}@{domain}",
        f"{first}_{last}@{domain}",
        f"{f}_{last}@{domain}",
        f"{f}{first[1]}{l}@{domain}",
        f"{first}{last}@{domain}",
        f"{first[:3]}.{l}@{domain}",
    ]
    # dedupe while preserving order
    return list(dict.fromkeys(patterns))

# ──────────────────────────────────────────────────────────────────────────────
# SMTP / DNS HELPERS
# ──────────────────────────────────────────────────────────────────────────────

def get_mx_hosts(domain: str) -> List[str]:
    try:
        answers = dns.resolver.resolve(domain, "MX")
        mxs = sorted(
            ((r.preference, r.exchange.to_text().rstrip("."))) for r in answers
        )
        return [h for _, h in mxs]
    except:
        for rd in ("A", "AAAA"):
            try:
                dns.resolver.resolve(domain, rd)
                return [domain]
            except:
                continue
    return []

def connect_smtp(mx: str, port: int = 25, use_tls: bool = False) -> socket.socket:
    sock = socket.create_connection((mx, port), timeout=SOCKET_TIMEOUT)
    sock.settimeout(SOCKET_TIMEOUT)
    if use_tls:
        sock.sendall(b"EHLO verifier\r\n")
        sock.sendall(b"STARTTLS\r\n")
        resp = sock.recv(1024)
        if not resp.startswith(b"220"):
            raise RuntimeError("STARTTLS failed")
        sock = ssl.wrap_socket(sock)
        sock.settimeout(SOCKET_TIMEOUT)
    return sock

def smtp_ehlo(sock: socket.socket, dom: str):
    sock.sendall(f"EHLO {dom}\r\n".encode())
    while True:
        ln = sock.recv(1024)
        if not ln.startswith(b"250-"):
            break

# single RCPT probe
def smtp_rcpt(sock: socket.socket, addr: str) -> (int, float):
    start = time.time()
    sock.sendall(f"RCPT TO:<{addr}>\r\n".encode())
    resp = sock.recv(1024)
    code = int(resp[:3])
    return code, time.time() - start

# ──────────────────────────────────────────────────────────────────────────────
# CATCH-ALL DETECTION
# ──────────────────────────────────────────────────────────────────────────────

def detect_catch_all(mx: str, dom: str) -> (bool, float):
    frm = FROM_ADDRESS_TEMPLATE.format(dom)
    timings = []
    for _ in range(NUM_CALIBRATE):
        fake = f"{uuid.uuid4().hex[:8]}@{dom}"
        try:
            sock = connect_smtp(mx, 587, True)
            smtp_ehlo(sock, dom)
            sock.sendall(f"MAIL FROM:<{frm}>\r\n".encode()); sock.recv(1024)
            code, delta = smtp_rcpt(sock, fake)
            sock.close()
            if code < 200 or code >= 300:
                return False, 0.0
            timings.append(delta)
        except:
            return False, 0.0
    return True, sum(timings)/len(timings)

# ──────────────────────────────────────────────────────────────────────────────
# SIMPLE vs TIMING VERIFY
# ──────────────────────────────────────────────────────────────────────────────

def verify_simple(mx: str, dom: str, addr: str) -> PerAddressResult:
    try:
        sock = connect_smtp(mx, 587, True)
        smtp_ehlo(sock, dom)
        sock.sendall(f"MAIL FROM:<verify@{dom}>\r\n".encode()); sock.recv(1024)
        code, _ = smtp_rcpt(sock, addr)
        sock.close()
        status = "valid" if 200 <= code < 300 else "invalid"
    except:
        status = "connect_failed"
    return PerAddressResult(addr=addr, mx=mx, method="simple", status=status,
                            catch_all=False, rcpt_time=None, score=1.0 if status=="valid" else 0.0)

def verify_timing(mx: str, dom: str, addr: str, avg: float) -> PerAddressResult:
    try:
        sock = connect_smtp(mx, 587, True)
        smtp_ehlo(sock, dom)
        sock.sendall(f"MAIL FROM:<verify@{dom}>\r\n".encode()); sock.recv(1024)
        code, delta = smtp_rcpt(sock, addr)
        sock.close()
        score = -abs(delta - avg)
        status = "valid"
    except:
        status, score = "connect_failed", float('-inf')
    return PerAddressResult(addr=addr, mx=mx, method="timing", status=status,
                            catch_all=True, rcpt_time=delta, score=score)

# ──────────────────────────────────────────────────────────────────────────────
# NEW ENDPOINT
# ──────────────────────────────────────────────────────────────────────────────

@app.post("/pattern-verify", response_model=PatternVerifyResponse)
def pattern_verify(req: PatternVerifyRequest):
    dom = req.domain.lower()
    mxs = get_mx_hosts(dom)
    if not mxs:
        raise HTTPException(400, f"No MX record for {dom}")
    mx = mxs[0]

    ca, avg = detect_catch_all(mx, dom)
    patterns = generate_patterns(req.full_name, dom)
    results = {}

    if not ca:
        for p in patterns:
            res = verify_simple(mx, dom, p)
            results[p] = res
            if res.status == "valid":
                return PatternVerifyResponse(chosen=res, all_results=results)
        # none valid
        return PatternVerifyResponse(chosen=res, all_results=results)

    for p in patterns:
        results[p] = verify_timing(mx, dom, p, avg)
    chosen = max(results.values(), key=lambda r: r.score)
    return PatternVerifyResponse(chosen=chosen, all_results=results)
