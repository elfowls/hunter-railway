import dns.resolver
import socket
import ssl
import time
import uuid
import email.utils
from collections import defaultdict
from typing import List, Dict, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr

# ──────────────────────────────────────────────────────────────────────────────
# FASTAPI SETUP & CORS
# ──────────────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="SMTP Pattern-Based Verifier API",
    description="Generate email patterns from a full name + domain, and verify via SMTP or timing.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ──────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────────────────────────────────────────
FROM_ADDRESS_TEMPLATE = "verify@{}"
SOCKET_TIMEOUT    = 5.0
NUM_CALIBRATE     = 3       # three fake RCPT probes for catch-all detection
TIMING_CUSHION    = 0.05    # tolerance for timing comparisons

FREE_MAIL_DOMAINS = {"gmail.com","yahoo.com","outlook.com","hotmail.com"}
DISPOSABLE_DOMAINS = {"mailinator.com","10minutemail.com"}
ROLE_LOCALS = {"admin","info","support","sales"}

# ──────────────────────────────────────────────────────────────────────────────
# REQUEST / RESPONSE MODELS
# ──────────────────────────────────────────────────────────────────────────────
class PatternVerifyRequest(BaseModel):
    full_name: str
    domain: str

class PerAddressResult(BaseModel):
    addr: EmailStr
    method: str
    status: str
    rcpt_time: Optional[float] = None
    score: Optional[float] = None
    catch_all: Optional[bool] = None

class PatternVerifyResponse(BaseModel):
    chosen: PerAddressResult
    all_results: Optional[Dict[str, PerAddressResult]] = None

# ──────────────────────────────────────────────────────────────────────────────
# SMTP / DNS HELPERS (same as before)
# ──────────────────────────────────────────────────────────────────────────────
def get_mx_hosts(domain: str) -> List[str]:
    try:
        answers = dns.resolver.resolve(domain, "MX")
        return [r.exchange.to_text().rstrip(".") for r in sorted(answers, key=lambda r: r.preference)]
    except:
        # fallback A/AAAA
        for rd in ("A","AAAA"):
            try:
                dns.resolver.resolve(domain, rd)
                return [domain]
            except:
                pass
    return []

def connect_smtp(mx_host: str, port: int=25, use_tls: bool=False) -> socket.socket:
    s = socket.create_connection((mx_host, port), timeout=SOCKET_TIMEOUT)
    s.settimeout(SOCKET_TIMEOUT)
    s.recv(1024)  # banner
    if use_tls:
        s.sendall(b"EHLO verifier\r\n")
        s.sendall(b"STARTTLS\r\n")
        resp = s.recv(1024)
        if not resp.startswith(b"220"):
            raise RuntimeError("STARTTLS failed")
        s = ssl.wrap_socket(s)
        s.settimeout(SOCKET_TIMEOUT)
    return s

def recv_line(s: socket.socket) -> str:
    buf = b""
    while not buf.endswith(b"\r\n"):
        ch = s.recv(1)
        if not ch:
            break
        buf += ch
    return buf.decode(errors="ignore").rstrip("\r\n")

def send_line(s: socket.socket, line: str):
    s.sendall((line + "\r\n").encode())

def smtp_ehlo(s: socket.socket, dom: str):
    send_line(s, f"EHLO {dom}")
    # drain multi-line
    while True:
        ln = recv_line(s)
        if not ln.startswith("250-"):
            break

def smtp_mail_from(s: socket.socket, frm: str):
    send_line(s, f"MAIL FROM:<{frm}>"); recv_line(s)

def smtp_rcpt_to(s: socket.socket, to_addr: str) -> (int, float):
    start = time.time()
    send_line(s, f"RCPT TO:<{to_addr}>")
    resp = recv_line(s)
    code = int(resp[:3]) if resp and resp[:3].isdigit() else 0
    return code, time.time() - start

def smtp_quit(s: socket.socket):
    try:
        send_line(s, "QUIT")
        recv_line(s)
    finally:
        s.close()

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
        f"{first[0:2]}{last}@{domain}",
        f"{f}.{last}@{domain}",
        f"{first[0:3]}@{domain}",
        f"{first}_{last}@{domain}",
        f"{f}_{last}@{domain}",
        f"{f}{first[1]}{last[0]}@{domain}",
        f"{first}{last}@{domain}",
        f"{first[0:3]}.{l}@{domain}"
    ]
    # remove duplicates and return
    return list(dict.fromkeys(patterns))

# ──────────────────────────────────────────────────────────────────────────────
# CATCH-ALL DETECTION (3 fakes)
# ──────────────────────────────────────────────────────────────────────────────
def detect_catch_all(mx: str, frm: str, dom: str) -> (bool, float):
    timings = []
    for _ in range(NUM_CALIBRATE):
        fake = f"{uuid.uuid4().hex[:8]}@{dom}"
        try:
            s = connect_smtp(mx)
            recv_line(s); smtp_ehlo(s, dom)
            smtp_mail_from(s, frm)
            code, delta = smtp_rcpt_to(s, fake)
            smtp_quit(s)
            if 200 <= code < 300:
                timings.append(delta)
            else:
                return False, 0.0
        except:
            return False, 0.0
    return True, sum(timings) / len(timings)

# ──────────────────────────────────────────────────────────────────────────────
# SIMPLE VERIFY (RCPT-only)
# ──────────────────────────────────────────────────────────────────────────────
def verify_simple(mx: str, frm: str, dom: str, addr: str) -> PerAddressResult:
    try:
        s = connect_smtp(mx)
        recv_line(s); smtp_ehlo(s, dom)
        smtp_mail_from(s, frm)
        code, delta = smtp_rcpt_to(s, addr)
        smtp_quit(s)
        status = "valid" if 200 <= code < 300 else "invalid"
    except:
        status, delta = "connect_failed", 0.0
    return PerAddressResult(
        addr=addr, method="simple", status=status,
        rcpt_time=delta, score=(1.0 if status=="valid" else 0.0),
        catch_all=False
    )

# ──────────────────────────────────────────────────────────────────────────────
# TIMING VERIFY (single RCPT + compare to avg)
# ──────────────────────────────────────────────────────────────────────────────
def verify_timing(mx: str, frm: str, dom: str, addr: str, avg: float) -> PerAddressResult:
    try:
        s = connect_smtp(mx)
        recv_line(s); smtp_ehlo(s, dom)
        smtp_mail_from(s, frm)
        code, delta = smtp_rcpt_to(s, addr)
        smtp_quit(s)
        # closer to avg ⇒ more likely real
        diff = abs(delta - avg)
        status = "valid"  # catch-all always accepts
    except:
        delta, diff = 0.0, float("inf")
        status = "connect_failed"
    return PerAddressResult(
        addr=addr, method="timing", status=status,
        rcpt_time=delta, score=-diff,  # negative diff so higher is better
        catch_all=True
    )

# ──────────────────────────────────────────────────────────────────────────────
# NEW ENDPOINT
# ──────────────────────────────────────────────────────────────────────────────
@app.post("/pattern-verify", response_model=PatternVerifyResponse)
def pattern_verify(req: PatternVerifyRequest):
    dom = req.domain.lower()
    mx_hosts = get_mx_hosts(dom)
    if not mx_hosts:
        raise HTTPException(400, f"No MX/A record for domain {dom}")
    mx = mx_hosts[0]
    frm = FROM_ADDRESS_TEMPLATE.format(dom)

    # 1) detect catch-all
    is_ca, avg = detect_catch_all(mx, frm, dom)

    # 2) generate all patterns
    patterns = generate_patterns(req.full_name, dom)

    results: Dict[str, PerAddressResult] = {}

    if not is_ca:
        # simple mode: try each until valid
        for p in patterns:
            res = verify_simple(mx, frm, dom, p)
            results[p] = res
            if res.status == "valid":
                return PatternVerifyResponse(chosen=res)
        # none valid:
        # return the last attempt
        last = results[patterns[-1]]
        return PatternVerifyResponse(chosen=last, all_results=results)

    # catch-all: timing mode
    # verify every pattern to get diff-based score
    for p in patterns:
        res = verify_timing(mx, frm, dom, p, avg)
        results[p] = res

    # pick the one with max score (i.e. smallest timing diff)
    chosen_addr = max(results.values(), key=lambda r: r.score)
    return PatternVerifyResponse(chosen=chosen_addr, all_results=results)
