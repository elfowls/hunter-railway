```python
import dns.resolver
import socket
import ssl
import time
import uuid
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
NUM_CALIBRATE = 3  # number of fake probes for catch-all detection
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
# PATTERN GENERATION (with length checks)
# ──────────────────────────────────────────────────────────────────────────────

def generate_patterns(full_name: str, domain: str) -> List[str]:
    parts = full_name.strip().lower().split()
    if not parts:
        return []

    first = parts[0]
    last = parts[-1]
    f = first[0] if len(first) >= 1 else ''
    l = last[0] if len(last) >= 1 else ''

    patterns: List[str] = []
    # basic full-name patterns
    patterns.append(f"{first}@{domain}")
    patterns.append(f"{last}@{domain}")
    patterns.append(f"{first}.{last}@{domain}")

    # initials
    if f and l:
        patterns.append(f"{f}{l}@{domain}")
        patterns.append(f"{f}.{l}@{domain}")

    # two-letter prefix
    if len(first) >= 2:
        patterns.append(f"{first[:2]}{last}@{domain}")

    # underscore variants
    patterns.append(f"{first}_{last}@{domain}")
    if f:
        patterns.append(f"{f}_{last}@{domain}")

    # combined letter patterns
    if len(first) > 1 and l:
        patterns.append(f"{f}{first[1]}{l}@{domain}")

    # concatenations
    patterns.append(f"{first}{last}@{domain}")

    # three-letter dot patterns
    if len(first) >= 3 and l:
        patterns.append(f"{first[:3]}.{l}@{domain}")

    # remove duplicates, preserve order
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
    except Exception:
        # fallback to A/AAAA
        for rd in ("A", "AAAA"):
            try:
                dns.resolver.resolve(domain, rd)
                return [domain]
            except Exception:
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
    timings: List[float] = []
    for _ in range(NUM_CALIBRATE):
        fake = f"{uuid.uuid4().hex[:8]}@{dom}"
        try:
            sock = connect_smtp(mx, 587, True)
            smtp_ehlo(sock, dom)
            sock.sendall(f"MAIL FROM:<{frm}>\r\n".encode()); sock.recv(1024)
            code, delta = smtp_rcpt(sock, fake)
            sock.close()
            # if RCPT rejects, not catch-all
            if code < 200 or code >= 300:
                return False, 0.0
            timings.append(delta)
        except Exception:
            return False, 0.0
    avg = sum(timings) / len(timings)
    return True, avg

# ──────────────────────────────────────────────────────────────────────────────
# SIMPLE VS TIMING VERIFY
# ──────────────────────────────────────────────────────────────────────────────

def verify_simple(mx: str, dom: str, addr: str) -> PerAddressResult:
    try:
        sock = connect_smtp(mx, 587, True)
        smtp_ehlo(sock, dom)
        sock.sendall(f"MAIL FROM:<verify@{dom}>\r\n".encode()); sock.recv(1024)
        code, _ = smtp_rcpt(sock, addr)
        sock.close()
        status = "valid" if 200 <= code < 300 else "invalid"
        score = 1.0 if status == "valid" else 0.0
    except Exception:
        status, score = "connect_failed", 0.0
    return PerAddressResult(
        addr=addr, mx=mx, method="simple", status=status,
        catch_all=False, rcpt_time=None, score=score
    )


def verify_timing(mx: str, dom: str, addr: str, avg: float) -> PerAddressResult:
    try:
        sock = connect_smtp(mx, 587, True)
        smtp_ehlo(sock, dom)
        sock.sendall(f"MAIL FROM:<verify@{dom}>\r\n".encode()); sock.recv(1024)
        code, delta = smtp_rcpt(sock, addr)
        sock.close()
        # score closer to avg => higher
        score = -abs(delta - avg)
        status = "valid"
    except Exception:
        delta, score = None, float('-inf')
        status = "connect_failed"
    return PerAddressResult(
        addr=addr, mx=mx, method="timing", status=status,
        catch_all=True, rcpt_time=delta, score=score
    )

# ──────────────────────────────────────────────────────────────────────────────
# NEW ENDPOINT
# ──────────────────────────────────────────────────────────────────────────────

@app.post("/pattern-verify", response_model=PatternVerifyResponse)
def pattern_verify(req: PatternVerifyRequest):
    dom = req.domain.lower().strip()
    mxs = get_mx_hosts(dom)
    if not mxs:
        raise HTTPException(status_code=400, detail=f"No MX record for {dom}")

    mx = mxs[0]
    catch_all, avg_time = detect_catch_all(mx, dom)
    patterns = generate_patterns(req.full_name, dom)
    if not patterns:
        raise HTTPException(status_code=400, detail="Could not generate any email patterns from full_name")

    results: Dict[str, PerAddressResult] = {}

    if not catch_all:
        last_res = None
        for p in patterns:
            res = verify_simple(mx, dom, p)
            results[p] = res
            last_res = res
            if res.status == "valid":
                return PatternVerifyResponse(chosen=res, all_results=results)
        # if none valid, return the last attempted
        return PatternVerifyResponse(chosen=last_res, all_results=results)

    # catch-all case: use timing
    for p in patterns:
        results[p] = verify_timing(mx, dom, p, avg_time)
    # pick highest score
    chosen = max(results.values(), key=lambda r: r.score or float('-inf'))
    return PatternVerifyResponse(chosen=chosen, all_results=results)
```
