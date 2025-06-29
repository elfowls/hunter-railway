import dns.resolver
import socket
import time
import random
import string
import email.utils
import uuid
import asyncio
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
    description="Batch-verify and find emails by name using SMTP-handshake + timing for catch-all domains, "
                "with extended metadata and CORS enabled.",
    version="1.5.0" # Updated version for improved email finding patterns
)

# ──────────────────────────────────────────────────────────────────────────────
# ADD CORS MIDDLEWARE
# ──────────────────────────────────────────────────────────────────────────────

origins = [
    "https://bounso.com",
    "http://bounso.com",
    "https://owlsquad.com",
    "http://owlsquad.com",
    "https://clay.com.com",
    "http://clay.com.com",
    "https://app.clay.com",
    # You may add local dev origins here for local development:
    # "http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:8000"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ──────────────────────────────────────────────────────────────────────────────
# CONFIGURATION (Adjust as needed)
# ──────────────────────────────────────────────────────────────────────────────

FROM_ADDRESS_TEMPLATE = "verify@{}"
SOCKET_TIMEOUT = 5.0 # Timeout for individual socket operations
NUM_CALIBRATE = 2    # Number of probes for catch-all detection and fake timing
RCPT_RETRIES = 1     # Retries for RCPT TO (though less common in successful direct verification)
TIMING_CUSHION = 0.05 # Threshold for timing difference (in seconds).

# Semaphore to limit concurrent SMTP connections to a single mail server.
# This is crucial to prevent mail servers from rate-limiting or blocking you.
# Adjust this value based on your observations and server tolerance.
# A lower value is safer; a higher value is faster (but riskier).
MAX_CONCURRENT_SMTP_CONNECTIONS_PER_MX = 5

FREE_MAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "aol.com", "icloud.com", "protonmail.com", "zoho.com"
}

DISPOSABLE_DOMAINS = {
    "mailinator.com", "10minutemail.com", "yopmail.com",
    "tempmail.com", "discard.email", "guerrillamail.com"
}

ROLE_LOCALS = {
    "admin", "administrator", "support", "info", "sales", "marketing",
    "billing", "webmaster", "postmaster", "contact", "help", "service"
}

# Dictionary to store semaphores per MX host to limit concurrent connections
mx_semaphores: Dict[str, asyncio.Semaphore] = defaultdict(lambda: asyncio.Semaphore(MAX_CONCURRENT_SMTP_CONNECTIONS_PER_MX))


# ──────────────────────────────────────────────────────────────────────────────
# REQUEST / RESPONSE MODELS (UNCHANGED, except for new FindEmailByNameRequest/Result)
# ──────────────────────────────────────────────────────────────────────────────

class VerifyRequest(BaseModel):
    batch_id: Optional[str] = None
    emails: List[EmailStr]

class PerAddressResult(BaseModel):
    addr: EmailStr
    mx: Optional[str] = None
    mx_provider: Optional[str] = None
    deliverability: Optional[str] = None
    score: Optional[float] = None
    free: Optional[bool] = None
    disposable: Optional[bool] = None
    role: Optional[bool] = None
    catch_all: Optional[bool] = None
    result: Optional[str] = None # 'valid', 'invalid', 'risky', 'risky_catch_all'
    verification_time: Optional[float] = None

    method: Optional[str] = None # 'timing', 'simple'
    status: Optional[str] = None # Detailed internal status: 'valid', 'invalid', 'unknown_temp', 'connect_failed', 'invalid_format', 'invalid_domain', 'unknown_catchall'
    rcpt_code: Optional[int] = None
    rcpt_time: Optional[float] = None
    rcpt_msg: Optional[str] = None
    data_code: Optional[int] = None
    data_msg: Optional[str] = None

class VerifyResponse(BaseModel):
    batch_id: Optional[str]
    results: Dict[EmailStr, PerAddressResult]

class FindEmailByNameRequest(BaseModel):
    batch_id: Optional[str] = None
    names_and_domains: List[Tuple[str, str]] # List of (full_name, domain) tuples

class FindEmailByNameResult(BaseModel):
    full_name: str
    domain: str
    found_email: Optional[EmailStr] = None
    verification_details: Optional[PerAddressResult] = None
    attempted_patterns: List[str] = []
    status: str # 'found', 'not_found', 'error'


# ──────────────────────────────────────────────────────────────────────────────
# HELPER FUNCTIONS: DNS + ASYNCHRONOUS RAW SMTP PROBES (UNCHANGED)
# ──────────────────────────────────────────────────────────────────────────────

def get_mx_hosts(domain: str) -> List[str]:
    try:
        answers = dns.resolver.resolve(domain, "MX")
        mx_list = [(r.preference, r.exchange.to_text().rstrip(".")) for r in answers]
        mx_list.sort(key=lambda x: x[0])
        return [host for (_, host) in mx_list]
    except Exception:
        try:
            dns.resolver.resolve(domain, "A")
            return [domain]
        except Exception:
            pass
        try:
            dns.resolver.resolve(domain, "AAAA")
            return [domain]
        except Exception:
            pass
    return []

async def connect_smtp_async(mx_host: str) -> Optional[Tuple[asyncio.StreamReader, asyncio.StreamWriter]]:
    reader, writer = None, None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(mx_host, 25), timeout=SOCKET_TIMEOUT
        )
        _ = await recv_line_async(reader)
        return reader, writer
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError) as e:
        if writer: writer.close()
        return None
    except Exception as e:
        if writer: writer.close()
        return None

async def recv_line_async(reader: asyncio.StreamReader) -> Optional[str]:
    try:
        data = await asyncio.wait_for(reader.readuntil(b"\r\n"), timeout=SOCKET_TIMEOUT)
        return data.decode(errors="ignore").rstrip("\r\n")
    except (asyncio.TimeoutError, asyncio.IncompleteReadError) as e:
        return None
    except Exception as e:
        return None

async def send_line_async(writer: asyncio.StreamWriter, line: str):
    writer.write((line + "\r\n").encode())
    await asyncio.wait_for(writer.drain(), timeout=SOCKET_TIMEOUT)

def parse_code(line: str) -> int:
    try:
        return int(line[:3])
    except Exception:
        return -1

async def smtp_ehlo_async(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, domain: str):
    await send_line_async(writer, f"EHLO {domain}")
    while True:
        line = await recv_line_async(reader)
        if line is None or not line.startswith("250-"):
            break

async def smtp_mail_from_async(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, from_addr: str) -> int:
    await send_line_async(writer, f"MAIL FROM:<{from_addr}>")
    resp = await recv_line_async(reader)
    return parse_code(resp) if resp else -1

async def smtp_rcpt_to_async(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, to_addr: str) -> Tuple[int, float, str]:
    start = time.time()
    await send_line_async(writer, f"RCPT TO:<{to_addr}>")
    resp = await recv_line_async(reader)
    elapsed = time.time() - start
    return parse_code(resp) if resp else -1, elapsed, resp or ""

async def smtp_quit_async(writer: asyncio.StreamWriter):
    try:
        await send_line_async(writer, "QUIT")
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass


# ──────────────────────────────────────────────────────────────────────────────
# CATCH-ALL DETECTION (ASYNC) (UNCHANGED)
# ──────────────────────────────────────────────────────────────────────────────

async def detect_catch_all_async(mx_host: str, domain: str, from_addr: str) -> bool:
    accepted_count = 0
    async with mx_semaphores[mx_host]:
        for _ in range(NUM_CALIBRATE):
            reader, writer = None, None
            try:
                reader, writer = await connect_smtp_async(mx_host)
                if reader is None or writer is None:
                    continue
                await smtp_ehlo_async(reader, writer, domain)
                code_mail = await smtp_mail_from_async(reader, writer, from_addr)
                if code_mail != 250:
                    continue
                rand_local = "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
                test_addr = f"{rand_local}@{domain}"
                code_rcpt, _, _ = await smtp_rcpt_to_async(reader, writer, test_addr)
                if 200 <= code_rcpt < 300:
                    accepted_count += 1
                elif 500 <= code_rcpt < 600:
                    return False
            finally:
                if writer: await smtp_quit_async(writer)
            await asyncio.sleep(0.05)
    return accepted_count == NUM_CALIBRATE

# ──────────────────────────────────────────────────────────────────────────────
# TIMING-BASED VALIDATION UNDER CATCH-ALL (ASYNC) (UNCHANGED)
# ──────────────────────────────────────────────────────────────────────────────

async def calibrate_fake_timing_async(mx_host: str, domain: str, from_addr: str) -> float:
    times = []
    async with mx_semaphores[mx_host]:
        for _ in range(NUM_CALIBRATE):
            reader, writer = None, None
            try:
                reader, writer = await connect_smtp_async(mx_host)
                if reader is None or writer is None:
                    continue
                await smtp_ehlo_async(reader, writer, domain)
                await smtp_mail_from_async(reader, writer, from_addr)
                rand_local = "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
                test_addr = f"{rand_local}@{domain}"
                code_rcpt, rcpt_time, _ = await smtp_rcpt_to_async(reader, writer, test_addr)
                if 200 <= code_rcpt < 300:
                    times.append(rcpt_time)
            finally:
                if writer: await smtp_quit_async(writer)
            await asyncio.sleep(0.05)
    return sum(times) / len(times) if times else 0.0

async def verify_with_timing_async(mx_host: str, domain: str, from_addr: str, target_addr: str, avg_fake_time: float) -> PerAddressResult:
    start_time = time.time()
    result = PerAddressResult(addr=target_addr)
    result.method = "timing"
    result.mx = mx_host
    result.catch_all = True

    reader, writer = None, None
    async with mx_semaphores[mx_host]:
        try:
            reader, writer = await connect_smtp_async(mx_host)
            if reader is None or writer is None:
                result.status = "connect_failed"
                return result
            await smtp_ehlo_async(reader, writer, domain)
            await smtp_mail_from_async(reader, writer, from_addr)
            code_rcpt, rcpt_time, rcpt_msg = await smtp_rcpt_to_async(reader, writer, target_addr)
            result.rcpt_code = code_rcpt
            result.rcpt_time = rcpt_time
            result.rcpt_msg = rcpt_msg

            if 500 <= code_rcpt < 600:
                result.status = "invalid"
            elif 400 <= code_rcpt < 500:
                result.status = "unknown_temp"
            else:
                if rcpt_time is not None and abs(rcpt_time - avg_fake_time) > TIMING_CUSHION:
                    result.status = "valid"
                else:
                    result.status = "invalid"
        finally:
            if writer: await smtp_quit_async(writer)

    fill_additional_fields(result, domain, catch_all=True)
    result.verification_time = time.time() - start_time
    return result

# ──────────────────────────────────────────────────────────────────────────────
# SIMPLE SMTP VALIDATION (NON-CATCH-ALL, ASYNC) (UNCHANGED)
# ──────────────────────────────────────────────────────────────────────────────

async def verify_simple_async(mx_host: str, domain: str, from_addr: str, target_addr: str) -> PerAddressResult:
    start_time = time.time()
    result = PerAddressResult(addr=target_addr)
    result.method = "simple"
    result.mx = mx_host
    result.catch_all = False

    reader, writer = None, None
    async with mx_semaphores[mx_host]:
        try:
            reader, writer = await connect_smtp_async(mx_host)
            if reader is None or writer is None:
                result.status = "connect_failed"
                return result

            await smtp_ehlo_async(reader, writer, domain)
            await smtp_mail_from_async(reader, writer, from_addr)

            code_rcpt, _, rcpt_msg = await smtp_rcpt_to_async(reader, writer, target_addr)
            result.rcpt_code = code_rcpt
            result.rcpt_msg = rcpt_msg

            if 500 <= code_rcpt < 600:
                result.status = "invalid"
                return result
            if 400 <= code_rcpt < 500:
                result.status = "unknown_temp"
                return result

            await send_line_async(writer, "DATA")
            data_resp = await recv_line_async(reader)
            data_code = parse_code(data_resp)
            result.data_code = data_code
            result.data_msg = data_resp

            if 500 <= data_code < 600:
                result.status = "invalid"
                return result

            if data_code == 354:
                await send_line_async(writer, f"Date: {email.utils.formatdate(localtime=False)}")
                await send_line_async(writer, f"From: <{from_addr}>")
                await send_line_async(writer, f"To: <{target_addr}>")
                await send_line_async(writer, "Subject: Verification Test")
                await send_line_async(writer, f"Message-ID: <{uuid.uuid4().hex}@{domain}>")
                await send_line_async(writer, "MIME-Version: 1.0")
                await send_line_async(writer, "Content-Type: text/plain; charset=UTF-8")
                await send_line_async(writer, "") # Empty line between headers and body
                await send_line_async(writer, "This is a minimal verification message.")
                await send_line_async(writer, ".") # End of data marker

                data2_resp = await recv_line_async(reader)
                data2_code = parse_code(data2_resp)
                result.data_code = data2_code
                result.data_msg = data2_resp

                if 200 <= data2_code < 300:
                    result.status = "valid"
                elif 500 <= data2_code < 600:
                    result.status = "invalid"
                else:
                    result.status = "unknown_temp"
            else:
                result.status = "unknown"

        except Exception:
            result.status = "connect_failed"
        finally:
            if writer:
                await smtp_quit_async(writer)

    fill_additional_fields(result, domain, catch_all=False)
    result.verification_time = time.time() - start_time
    return result

# ──────────────────────────────────────────────────────────────────────────────
# ADDITIONAL FIELD CALCULATION (UNCHANGED)
# ──────────────────────────────────────────────────────────────────────────────

def infer_mx_provider(mx_host: str) -> str:
    mx_lower = (mx_host or "").lower()
    if "google" in mx_lower or mx_lower.endswith("gmail.com"):
        return "Google"
    if "outlook" in mx_lower or "office365" in mx_lower or "hotmail" in mx_lower or "live" in mx_lower:
        return "Microsoft"
    return "Other/Unknown"

def infer_free(domain: str) -> bool:
    return domain.lower() in FREE_MAIL_DOMAINS

def infer_disposable(domain: str) -> bool:
    return domain.lower() in DISPOSABLE_DOMAINS

def infer_role(local: str) -> bool:
    return local.lower() in ROLE_LOCALS

def infer_deliverability(status: str) -> str:
    if status == "valid":
        return "deliverable"
    if status == "invalid":
        return "undeliverable"
    return "risky"

def infer_score(status: str) -> float:
    if status == "valid":
        return 1.0
    if status == "invalid":
        return 0.0
    return 0.5

def fill_additional_fields(result: PerAddressResult, domain: str, catch_all: bool):
    """
    Fills in auxiliary fields for the verification result.
    """
    result.mx_provider = infer_mx_provider(result.mx or "")
    result.catch_all = catch_all
    # Initial deliverability/score based on direct SMTP status
    result.deliverability = infer_deliverability(result.status or "")
    result.score = infer_score(result.status or "")

    local_part = result.addr.split("@", 1)[0]
    result.free = infer_free(domain or "")
    result.disposable = infer_disposable(domain or "")
    result.role = infer_role(local_part)

    # Refine overall 'result' field (valid/invalid/risky)
    if result.status == "valid":
        if result.catch_all:
            result.result = "risky_catch_all"
            result.score = 0.96
            result.deliverability = "deliverable"
        else:
            result.result = "valid"
            result.score = 1.0
            result.deliverability = "deliverable"
    elif result.status == "invalid":
        result.result = "invalid"
        result.score = 0.0
        result.deliverability = "undeliverable"
    elif result.status in ["unknown_temp", "connect_failed", "invalid_format", "invalid_domain", "unknown_catchall"]:
        result.result = "risky"
        result.score = 0.3
        result.deliverability = "risky"
    else:
        result.result = "risky"
        result.score = 0.5
        result.deliverability = "risky"


# ──────────────────────────────────────────────────────────────────────────────
# EMAIL PATTERN GENERATION (IMPROVED)
# ──────────────────────────────────────────────────────────────────────────────

def generate_email_patterns(full_name: str, domain: str) -> List[str]:
    """
    Generates a prioritized list of common email address patterns for a given full name and domain.
    Attempts to parse name into first, middle, last.
    """
    cleaned_name = full_name.lower().strip().replace("'", "").replace("-", "") # Clean up common non-alpha chars
    parts = cleaned_name.split()

    first = parts[0] if parts else ""
    last = parts[-1] if len(parts) > 1 else ""
    
    # Handle middle names/initials more carefully.
    # If there are exactly 3 parts, assume middle_name_or_initial is parts[1]
    # If more than 3, parts[1:-1] could be middle names, take first initial of first middle name
    middle_initial = ""
    if len(parts) > 2:
        middle_initial = parts[1][0] if parts[1] else "" # First letter of assumed middle part

    patterns = []
    
    # --- Most Common Patterns ---
    if first and last:
        patterns.append(f"{first}.{last}@{domain}")         # firstname.lastname@domain.com
        patterns.append(f"{first}{last}@{domain}")          # firstnamelastname@domain.com
        patterns.append(f"{first[0]}{last}@{domain}")       # flastname@domain.com (e.g., jsmith)
        patterns.append(f"{first}_{last}@{domain}")         # firstname_lastname@domain.com
        patterns.append(f"{last}.{first}@{domain}")         # lastname.firstname@domain.com
        patterns.append(f"{first}.{last[0]}@{domain}")      # firstname.l@domain.com (e.g., john.d)
        patterns.append(f"{first[0]}.{last[0]}@{domain}")   # f.l@domain.com (e.g., j.d)
        patterns.append(f"{first}{last[0]}@{domain}")       # firstnamel@domain.com (e.g., johnd)
        patterns.append(f"{last}{first[0]}@{domain}")       # lastnamf@domain.com (e.g., smithj)
        patterns.append(f"{first[0]}{last[0]}@{domain}")    # js@domain.com
        patterns.append(f"{first[0]}.{last}@{domain}")     # j.smith@domain.com

    # Simple First or Last Name
    if first:
        patterns.append(f"{first}@{domain}")                # firstname@domain.com
    if last:
        patterns.append(f"{last}@{domain}")                 # lastname@domain.com

    # Patterns with middle initial/name (if available and relevant)
    if first and middle_initial and last:
        patterns.append(f"{first}{middle_initial}{last}@{domain}") # fmlastname@domain.com (e.g., jprana)
        patterns.append(f"{first}.{middle_initial}.{last}@{domain}") # f.m.lastname@domain.com
        patterns.append(f"{first}.{middle_initial}{last}@{domain}") # f.mlastname@domain.com
        patterns.append(f"{first[0]}{middle_initial}{last[0]}@{domain}") # fml@domain.com (e.g., jpr)
        patterns.append(f"{first[0]}{middle_initial}.{last}@{domain}") # fm.lastname@domain.com

    # Other common or short forms
    if first and len(first) > 3:
        patterns.append(f"{first[:3]}@{domain}") # e.g., har@domain.com
    if first and last and len(first) > 3 and len(last) > 3:
        patterns.append(f"{first[:3]}.{last[:3]}@{domain}") # e.g., har.ran@domain.com

    # Remove duplicates while preserving order
    seen = set()
    unique_patterns = []
    for email_pattern in patterns:
        if email_pattern not in seen:
            unique_patterns.append(email_pattern)
            seen.add(email_pattern)
            
    return unique_patterns


# ──────────────────────────────────────────────────────────────────────────────
# MAIN ASYNCHRONOUS VERIFICATION LOGIC (UNCHANGED)
# ──────────────────────────────────────────────────────────────────────────────

async def _verify_domain_emails_async(domain: str, addrs: List[str], mx_host: str, from_addr: str) -> Dict[str, PerAddressResult]:
    """
    Internal asynchronous helper to verify all emails for a single domain.
    This runs sequentially for addresses within a domain, but concurrently across domains.
    """
    domain_results: Dict[str, PerAddressResult] = {}
    
    is_catch_all = await detect_catch_all_async(mx_host, domain, from_addr)

    if not is_catch_all:
        # Create tasks for concurrent verification within this non-catch-all domain
        tasks = [verify_simple_async(mx_host, domain, from_addr, addr) for addr in addrs]
        results_list = await asyncio.gather(*tasks, return_exceptions=True)
        for i, res_or_exc in enumerate(results_list):
            addr = addrs[i]
            if isinstance(res_or_exc, Exception):
                res = PerAddressResult(addr=addr, status="unknown_error", result="risky")
                print(f"Error verifying {addr}: {res_or_exc}") # Log error for debugging
            else:
                res = res_or_exc
            domain_results[addr] = res
    else:
        avg_fake_time = await calibrate_fake_timing_async(mx_host, domain, from_addr)
        if avg_fake_time <= 0: # Calibration failed or no accepted fake probes
            for addr in addrs:
                res = PerAddressResult(addr=addr, status="unknown_catchall")
                res.mx = mx_host
                fill_additional_fields(res, domain, catch_all=True)
                res.verification_time = 0.0
                domain_results[addr] = res
        else:
            # Create tasks for concurrent verification within this catch-all domain
            tasks = [verify_with_timing_async(mx_host, domain, from_addr, addr, avg_fake_time) for addr in addrs]
            results_list = await asyncio.gather(*tasks, return_exceptions=True)
            for i, res_or_exc in enumerate(results_list):
                addr = addrs[i]
                if isinstance(res_or_exc, Exception):
                    res = PerAddressResult(addr=addr, status="unknown_error", result="risky")
                    print(f"Error verifying {addr}: {res_or_exc}") # Log error for debugging
                else:
                    res = res_or_exc
                domain_results[addr] = res
    return domain_results


async def verify_bulk_async(address_list: List[str]) -> Dict[str, PerAddressResult]:
    domains = defaultdict(list)
    results: Dict[str, PerAddressResult] = {} # Initialize results dict here

    for addr_orig in address_list:
        addr = addr_orig.lower()
        if "@" not in addr:
            results[addr_orig] = PerAddressResult(addr=addr_orig, status="invalid_format")
            fill_additional_fields(results[addr_orig], "", catch_all=False)
            results[addr_orig].verification_time = 0.0
        else:
            local, domain = addr.rsplit("@", 1)
            domains[domain].append(addr_orig)

    tasks = []
    for domain_key, addrs_for_domain in domains.items():
        if domain_key is None: # This block handles invalid format that might have slipped through early
             # Already handled above if 'continue' was not hit. This should ideally be empty.
             pass

        # Synchronous MX lookup - running in a threadpool to avoid blocking event loop
        mx_hosts = await asyncio.to_thread(get_mx_hosts, domain_key)

        if not mx_hosts:
            for addr in addrs_for_domain:
                results[addr] = PerAddressResult(addr=addr, status="invalid_domain")
                fill_additional_fields(results[addr], domain_key, catch_all=False)
                results[addr].verification_time = 0.0
            continue

        mx_host = mx_hosts[0]
        from_addr = FROM_ADDRESS_TEMPLATE.format(domain_key)

        tasks.append(_verify_domain_emails_async(domain_key, addrs_for_domain, mx_host, from_addr))

    concurrent_domain_results = await asyncio.gather(*tasks, return_exceptions=True)

    for domain_res_dict_or_exception in concurrent_domain_results:
        if isinstance(domain_res_dict_or_exception, Exception):
            print(f"Error processing a domain task: {domain_res_dict_or_exception}")
        else:
            results.update(domain_res_dict_or_exception)

    return results


# ──────────────────────────────────────────────────────────────────────────────
# NEW API ROUTE: FIND EMAIL BY NAME
# ──────────────────────────────────────────────────────────────────────────────

@app.post("/find_email_by_name", response_model=List[FindEmailByNameResult])
async def find_email_by_name_endpoint(request: FindEmailByNameRequest):
    """
    Generates common email patterns for a full name and domain,
    then verifies them, returning the first valid one found.
    """
    if len(request.names_and_domains) > 10: # Limit for batch size here
        raise HTTPException(status_code=400, detail="Maximum 10 name/domain pairs per request for find_email_by_name.")

    all_results: List[FindEmailByNameResult] = []

    # Process each name/domain pair concurrently
    tasks = []
    for full_name, domain in request.names_and_domains:
        tasks.append(_find_single_email_by_name_task(full_name, domain))
    
    all_results = await asyncio.gather(*tasks)
    return all_results


async def _find_single_email_by_name_task(full_name: str, domain: str) -> FindEmailByNameResult:
    """
    Generates patterns for a single name/domain and verifies them sequentially until one is found.
    """
    response = FindEmailByNameResult(full_name=full_name, domain=domain, status="not_found")
    
    # 1. Generate patterns
    patterns = generate_email_patterns(full_name, domain)
    response.attempted_patterns = patterns # Record all patterns attempted

    if not patterns:
        response.status = "error"
        response.verification_details = PerAddressResult(
            addr=f"@{domain}", status="invalid_name_patterns", result="risky",
            mx=None, verification_time=0.0
        )
        return response

    # 2. Get MX hosts once for the domain
    mx_hosts = await asyncio.to_thread(get_mx_hosts, domain)
    if not mx_hosts:
        response.status = "not_found"
        response.verification_details = PerAddressResult(
            addr=f"@{domain}", status="invalid_domain", result="invalid",
            mx=None, verification_time=0.0
        )
        return response
    mx_host = mx_hosts[0]
    from_addr = FROM_ADDRESS_TEMPLATE.format(domain)

    # 3. Detect catch-all status once for the domain
    is_catch_all = await detect_catch_all_async(mx_host, domain, from_addr)
    avg_fake_time = 0.0
    if is_catch_all:
        avg_fake_time = await calibrate_fake_timing_async(mx_host, domain, from_addr)
        if avg_fake_time <= 0: # Calibration failed
             response.status = "not_found"
             response.verification_details = PerAddressResult(
                addr=f"@{domain}", status="unknown_catchall", result="risky",
                mx=mx_host, catch_all=True, verification_time=0.0
             )
             return response

    # 4. Verify patterns sequentially with early exit
    for pattern_email in patterns:
        try:
            # Perform a full verification for the pattern
            if not is_catch_all:
                verification_result = await verify_simple_async(mx_host, domain, from_addr, pattern_email)
            else:
                verification_result = await verify_with_timing_async(mx_host, domain, from_addr, pattern_email, avg_fake_time)
            
            # Check if the result is considered "valid" or "likely deliverable"
            if verification_result.result == "valid" or verification_result.result == "risky_catch_all":
                response.found_email = pattern_email
                response.verification_details = verification_result
                response.status = "found"
                return response # FOUND AND EXIT EARLY!

        except Exception as e:
            # Log error but don't stop the search for other patterns
            print(f"Error verifying pattern {pattern_email}: {e}")
            pass # Continue to next pattern if an error occurs

    return response # No valid email found after trying all patterns


# ──────────────────────────────────────────────────────────────────────────────
# EXISTING API ROUTE: BULK VERIFY (UNCHANGED)
# ──────────────────────────────────────────────────────────────────────────────

@app.post("/verify", response_model=VerifyResponse)
async def batch_verify(request: VerifyRequest):
    """
    API endpoint to batch-verify email addresses.
    """
    if len(request.emails) > 200:
        raise HTTPException(status_code=400, detail="Maximum 200 emails per request.")
    
    raw_results = await verify_bulk_async(request.emails)
    
    final_results_map = {}
    for email_req in request.emails:
        final_results_map[email_req] = raw_results.get(email_req, PerAddressResult(addr=email_req, status="unknown", result="risky", verification_time=0.0))
    
    return VerifyResponse(batch_id=request.batch_id, results=final_results_map)
