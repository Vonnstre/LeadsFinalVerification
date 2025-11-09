#!/usr/bin/env python3
"""
enrich.py — async domain-level enricher with SMTP verification

Quick summary
-------------
- Reads a CSV (default: high_confidence_pi_mt_firms.csv)
- Performs SMTP-level mail server checks (true mailbox validation).
- Scrapes a small set of contact pages once per domain (cached).
- Generates intelligent attorney-name-based email guesses from the business name.
- Outputs enriched.csv and a sample_top100.csv.

Dependencies (put in requirements.txt):
  aiohttp
  dnspython
  beautifulsoup4
  (Optional but highly recommended: lxml for faster scraping)

Usage:
  python3 enrich.py --input high_confidence_pi_mt_firms.csv --output enriched.csv
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import logging
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import aiohttp
import dns.resolver
import dns.exception
import smtplib
from bs4 import BeautifulSoup

# ---------------------- configuration ----------------------
LOG = logging.getLogger("enricher")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-']+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", re.I)
TLD_CANDIDATES = [".com", ".co.uk", ".uk", ".net", ".io", ".co", ".org"]
CONTACT_PAGES = ["/", "/contact", "/contact-us", "/about", "/team", "/about-us", "/people", "/staff"]
ROLE_LOCALPARTS = {
    "admin", "administrator", "postmaster", "hostmaster", "info", "contact", "sales", "support",
    "help", "billing", "webmaster", "noreply", "no-reply", "newsletter", "hello"
}
COMMON_DISPOSABLE = {"mailinator.com", "tempmail.com", "10minutemail.com", "yopmail.com", "dispostable.com"}
HTML_HEURISTIC_BYTES = 2048
# Common Law Firm Suffixes to remove before parsing names
FIRM_SUFFIXES = re.compile(r"\b(P\.A|PLLC|LLC|LLP|LTD|PC|INC|LAWFIRM|LAW|ATTORNEYS|GROUP|ASSOCIATES|COUNSEL)\b", re.I)
DEFAULT_SENDER_EMAIL = "test@example.com" # Required for SMTP handshake

# scoring weights (updated to heavily favor SMTP verification)
WEIGHTS = {
    "scraped": 50,
    "given": 40,
    "generated": 5,
    "email_verified_ok": 100, # NEW: High weight for confirmed mailbox (SMTP check)
    "company_present": 5,
    "is_disposable_penalty": -150, # Increased penalty
    "is_role_penalty": -30,
    "mx_ok_only": 20 # Weight for MX existing but SMTP failing/unknown
}

# ---------------------- utilities ----------------------

def slug_company(name: str) -> str:
    if not name:
        return ""
    s = name.lower()
    s = re.sub(r"[^0-9a-z\s]", " ", s)
    s = re.sub(r"\b(ltd|limited|co|company|inc|llc|plc)\b", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s.replace(" ", "") if s else ""

def gen_domains(company_name: str) -> List[str]:
    # Use existing slug logic for base domains
    base = slug_company(company_name)
    out: List[str] = []
    if base:
        for t in TLD_CANDIDATES:
            out.append(base + t)
        words = re.findall(r"[a-z0-9]+", company_name.lower())
        if len(words) > 1:
            out.append("".join(words) + ".com")
    # dedupe while keeping order
    seen = set()
    dedup = []
    for d in out:
        if d not in seen:
            dedup.append(d)
            seen.add(d)
    return dedup

def gen_attorney_emails(business_name: str, domains: List[str]) -> List[Tuple[str, str]]:
    """Intelligently generates name-based email candidates."""
    name_str = business_name
    # 1. Clean up legal suffixes
    # FIX: Removed the redundant 'flags=re.I' argument since FIRM_SUFFIXES is already compiled with it.
    name_str = re.sub(FIRM_SUFFIXES, '', name_str).strip()
    # 2. Keep only potential names/words before any "Law" or "Group" terms
    name_str = re.sub(r"^(.*?)(LAW|GROUP|ASSOCIATES|PC)", r"\1", name_str, flags=re.I).strip()
    # 3. Clean up separators and extra words
    name_str = re.sub(r"[\-,\.&]", " ", name_str).strip()
    words = [w.lower() for w in re.findall(r"\b[a-zA-Z]+\b", name_str) if len(w) > 1]
    
    candidates: List[Tuple[str, str]] = []

    # Get the last two words as potential last name and first name/initial
    if len(words) >= 2:
        last_name = words[-1]
        first_name_candidate = words[-2]
    elif len(words) == 1:
        last_name = words[-1]
        first_name_candidate = ""
    else:
        # Fallback to general contacts if no names found
        return [(f"{lp}@{d}", "generated") for d in domains[:2] for lp in ("contact", "info", "hello")]

    # Generate patterns for top 3 domains
    name_patterns = []
    if first_name_candidate:
        name_patterns = [
            f"{first_name_candidate}@{last_name}",      # first@domain.com
            f"{first_name_candidate[0]}.{last_name}", # f.last@domain.com
            f"{first_name_candidate[0]}{last_name}"   # flast@domain.com
        ]
    
    # Generic partner patterns (e.g., just last name)
    name_patterns.append(f"{last_name}")

    # Combine with domains
    for d in domains[:3]:
        for pattern in name_patterns:
            # Handle the case where the pattern is already a full local-part (e.g., 'smith' or 'john.smith')
            local_part = pattern.rsplit('@', 1)[0]
            candidates.append((f"{local_part}@{d}", "generated"))
    
    # Add general contacts
    for d in domains[:2]:
        for lp in ("contact", "info", "hello"):
            candidates.append((f"{lp}@{d}", "generated"))
            
    # Dedupe
    seen = set()
    deduped = []
    for em, src in candidates:
        if em not in seen:
            deduped.append((em, src))
            seen.add(em)
    
    return deduped


def _looks_like_html(txt: str) -> bool:
    if not txt:
        return False
    sample = txt.lstrip()[:HTML_HEURISTIC_BYTES]
    return bool(re.search(r"<[a-zA-Z!\/]", sample) or ("@" in sample))


def validate_syntax(email: str) -> Tuple[bool, Optional[str]]:
    if not email or "@" not in email:
        return False, None
    m = EMAIL_RE.fullmatch(email.strip())
    return (m is not None, email.strip().lower() if m else None)


# ---------------------- Domain Resolver (MX + SMTP Verification) ----------------------


class DomainResolver:
    """Handles thread-safe MX and SMTP lookups."""
    def __init__(self, timeout: float = 5.0, threads: int = 8):
        self.timeout = float(timeout)
        self._mx_cache: Dict[str, List[Tuple[int, str]]] = {}
        self._smtp_cache: Dict[str, bool] = {} # True if accepted, False otherwise
        self._executor = ThreadPoolExecutor(max_workers=threads)

    def _resolve_mx_sync(self, domain: str) -> List[Tuple[int, str]]:
        try:
            ans = dns.resolver.resolve(domain, "MX", lifetime=self.timeout)
            pairs = sorted([(int(r.preference), str(r.exchange).rstrip(".")) for r in ans], key=lambda x: x[0])
            return pairs
        except dns.exception.Timeout:
            return []
        except Exception:
            return []

    def _resolve_smtp_sync(self, email: str, mx_pairs: List[Tuple[int, str]]) -> bool:
        """Performs a synchronous SMTP handshake to verify the mailbox."""
        if not mx_pairs:
            return False
            
        local_part, domain = email.rsplit("@", 1)
        
        # Try all MX servers in order of preference
        for _pref, mx_server in mx_pairs:
            try:
                # Use smtplib.SMTP for the sync operation in the thread pool
                with smtplib.SMTP(mx_server, 25, timeout=self.timeout) as server:
                    server.local_hostname = domain # Identify as a local host for the domain
                    server.ehlo()
                    # Some servers require TLS, but we keep it simple for a free solution
                    # server.starttls()
                    server.mail(DEFAULT_SENDER_EMAIL)
                    
                    # The VRFY command is often disabled; RCPT TO is the reliable method
                    code, message = server.rcpt(email)
                    
                    # 250 (Requested mail action okay, completed) is success
                    # 550 (No such user here) is failure
                    # Codes 4xx are temporary failure and will be treated as failure/unknown
                    if code == 250:
                        return True
                    
            except smtplib.SMTPConnectError:
                # MX server did not connect/accept connections on port 25
                continue
            except Exception:
                # Other errors (timeout, etc.)
                continue
                
        return False # Failed all MX servers

    async def get_mx(self, domain: str) -> List[Tuple[int, str]]:
        d = domain.lower().strip()
        if d in self._mx_cache:
            return self._mx_cache[d]
        loop = asyncio.get_event_loop()
        pairs = await loop.run_in_executor(self._executor, self._resolve_mx_sync, d)
        self._mx_cache[d] = pairs
        return pairs

    async def get_smtp_status(self, email: str, mx_pairs: List[Tuple[int, str]]) -> bool:
        e = email.lower().strip()
        if e in self._smtp_cache:
            return self._smtp_cache[e]
        
        loop = asyncio.get_event_loop()
        is_verified = await loop.run_in_executor(self._executor, self._resolve_smtp_sync, e, mx_pairs)
        self._smtp_cache[e] = is_verified
        return is_verified

    def shutdown(self):
        try:
            self._executor.shutdown(wait=False)
        except Exception:
            pass

# ---------------------- scraping ----------------------


async def scrape_domain_for_emails(session: aiohttp.ClientSession, domain: str, http_timeout: float, semaphore: asyncio.Semaphore) -> Set[str]:
    found: Set[str] = set()
    headers = {"User-Agent": session.headers.get("User-Agent", "enricher/1.0"), "Accept": "text/html,application/xhtml+xml"}
    schemes = ["https://", "http://"]

    async with semaphore:
        for scheme in schemes:
            base = scheme + domain.rstrip("/")
            for p in CONTACT_PAGES:
                url = base + p
                try:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=http_timeout), headers=headers) as resp:
                        if resp.status != 200:
                            continue
                        ct = resp.headers.get("Content-Type", "")
                        if "html" not in ct.lower() and "xml" not in ct.lower():
                            continue
                        txt = await resp.text(errors="replace")
                        if not _looks_like_html(txt):
                            continue
                        
                        # Use lxml parser if available for speed, otherwise use default
                        parser = "lxml" if "lxml" in sys.modules else "html.parser"
                        soup = BeautifulSoup(txt, parser)
                        
                        # mailto links
                        for a in soup.select("a[href^=mailto]"):
                            href = a.get("href", "")
                            m = re.search(r"mailto:([^?]+)", href, re.I)
                            if m:
                                found.add(m.group(1).strip().lower())
                        
                        # any email-like text
                        for e in EMAIL_RE.findall(soup.get_text(" ", strip=True)):
                            found.add(e.lower())
                        
                        # Prioritize finding high-confidence contact
                        if found:
                            return found
                except asyncio.CancelledError:
                    raise
                except Exception:
                    continue
    return found


# ---------------------- scoring ----------------------


def score_record(source: str, mx_ok: bool, email_verified_ok: bool, is_disposable: bool, is_role: bool, scraped: bool, company_present: bool) -> int:
    score = 0
    
    # 1. Base Score (Source)
    score += WEIGHTS.get(source, 0)
    
    # 2. Quality Checks
    if email_verified_ok:
        score += WEIGHTS["email_verified_ok"]
    elif mx_ok:
        score += WEIGHTS["mx_ok_only"]
        
    # 3. Contextual Bonus
    if company_present:
        score += WEIGHTS["company_present"]
        
    # 4. Penalties
    if is_disposable:
        score += WEIGHTS["is_disposable_penalty"]
    if is_role:
        score += WEIGHTS["is_role_penalty"]
        
    return max(0, min(200, int(score))) # Max score increased due to verification weight


# ---------------------- enrichment flow ----------------------


async def enrich(
    input_path: Path,
    output_path: Path,
    sample_path: Path,
    target: Optional[int],
    concurrency: int,
    http_timeout: float,
    mx_timeout: float,
    user_agent: str,
    keep_role: bool,
    disposable_file: Optional[Path],
):
    # load disposables
    disposable_set: Set[str] = set(COMMON_DISPOSABLE)
    if disposable_file and disposable_file.exists():
        try:
            with disposable_file.open("r", encoding="utf-8") as f:
                for ln in f:
                    s = ln.strip().lower()
                    if s:
                        disposable_set.add(s)
        except Exception:
            LOG.warning("failed to load disposable file; continuing with builtin list")

    resolver = DomainResolver(timeout=mx_timeout, threads=max(8, min(32, concurrency * 2)))

    # connector & semaphore and timeouts
    conn = aiohttp.TCPConnector(limit=max(2, concurrency), limit_per_host=max(2, concurrency // 4))
    timeout = aiohttp.ClientTimeout(total=http_timeout)
    http_semaphore = asyncio.Semaphore(max(4, concurrency // 4))

    # read input and exact dedupe by company||email
    raw_rows: List[Dict[str, str]] = []
    seen_rows: Set[str] = set()
    
    # Define expected input fields to handle the user's uploaded CSV structure
    field_map = {
        'company': ['business_name', 'CompanyName', 'company'],
        'email': ['email', 'Email'],
        'address': ['address'],
        'city': ['city'],
        'state': ['state'],
        'zip': ['zip'],
    }
    
    with input_path.open(newline="", encoding="utf-8", errors="replace") as inf:
        reader = csv.DictReader(inf)
        fieldnames = reader.fieldnames if reader.fieldnames else []
        
        def safe_get(row, keys):
            for key in keys:
                if key in row and row[key]:
                    return row[key].strip()
            return ""

        for row in reader:
            company = safe_get(row, field_map['company'])
            in_email = safe_get(row, field_map['email'])
            
            if not company and not in_email:
                continue
                
            key = f"{company}||{in_email}"
            if key in seen_rows:
                continue
            seen_rows.add(key)
            
            # Map all useful fields from the input CSV
            new_row = {
                "company": company,
                "input_email": in_email,
                "address": safe_get(row, field_map['address']),
                "city": safe_get(row, field_map['city']),
                "state": safe_get(row, field_map['state']),
                "zip": safe_get(row, field_map['zip']),
                **row # Keep original columns for context/debugging
            }
            raw_rows.append(new_row)

    total_rows = len(raw_rows)
    LOG.info("Loaded rows: %d (after exact dedupe). Input file: %s", total_rows, input_path.name)
    
    if total_rows == 0:
        LOG.info("No rows to process. Exiting.")
        resolver.shutdown()
        return


    # caches & counters
    enriched_by_email: Dict[str, Dict] = {}
    domain_scrape_cache: Dict[str, Set[str]] = {}
    lock = asyncio.Lock()
    found_count = 0
    processed_rows = 0
    scraped_found = 0

    mx_hits = 0
    mx_misses = 0
    smtp_verified = 0
    smtp_unverified = 0
    scrape_success = 0
    scrape_failures = 0

    # process each row (company + optional email)
    async def process_row(r: Dict[str, str], session: aiohttp.ClientSession):
        nonlocal found_count, processed_rows, scraped_found, mx_hits, mx_misses, smtp_verified, smtp_unverified, scrape_success, scrape_failures
        
        company = r.get("company", "").strip()
        in_email = r.get("input_email", "").strip()
        
        company_present = bool(company)
        candidate_emails: List[Tuple[str, str]] = []

        # 1. Use input email if valid
        if in_email:
            ok, norm = validate_syntax(in_email)
            if ok and norm:
                candidate_emails.append((norm, "given"))

        # 2. Generate intelligent name-based emails
        if company_present:
            domains = gen_domains(company)
            # This generates both attorney and generic emails
            candidate_emails.extend(gen_attorney_emails(company, domains))
        
        # Domains to check (for MX/SMTP/Scrape)
        domains_to_check: Set[str] = set()
        for em, _src in candidate_emails:
            if "@" in em:
                domains_to_check.add(em.rsplit("@", 1)[-1].lower())
        
        # MX checks with local cache
        domain_mx_map: Dict[str, List[Tuple[int, str]]] = {}
        for dom in domains_to_check:
            mx_pairs = await resolver.get_mx(dom)
            domain_mx_map[dom] = mx_pairs
            if mx_pairs:
                mx_hits += 1
            else:
                mx_misses += 1

        # schedule scrapes for domains not yet cached
        scraped_emails: Set[str] = set()
        domains_to_scrape = [d for d in domain_mx_map.keys() if d not in domain_scrape_cache and domain_mx_map[d]] # Only scrape domains with MX records
        
        task_map: Dict[asyncio.Task, str] = {}
        for d in domains_to_scrape:
            t = asyncio.create_task(scrape_domain_for_emails(session, d, http_timeout, http_semaphore))
            task_map[t] = d

        if task_map:
            results = await asyncio.gather(*list(task_map.keys()), return_exceptions=True)
            for t, res in zip(list(task_map.keys()), results):
                dom = task_map[t]
                if isinstance(res, set) and res:
                    domain_scrape_cache[dom] = res
                    scraped_emails.update(res)
                    scrape_success += 1
                else:
                    domain_scrape_cache[dom] = set()
                    scrape_failures += 1

        # include any cached scrapes
        for d, cached in domain_scrape_cache.items():
            if cached:
                scraped_emails.update(cached)

        if scraped_emails:
            scraped_found += len(scraped_emails)

        # assemble final candidate list, scraped first
        final_candidates: List[Tuple[str, str, bool]] = []
        for se in sorted(scraped_emails):
            final_candidates.append((se, "scraped", True))
        for em, src in candidate_emails:
            em_norm = em.lower()
            if em_norm in scraped_emails:
                continue
            final_candidates.append((em_norm, src, False))
        
        # --- SMTP Verification ---
        # Perform SMTP check for all unique email candidates that are not disposable
        smtp_check_tasks: Dict[str, asyncio.Task] = {}
        for email, _, _ in final_candidates:
            local, domain = email.rsplit("@", 1)
            is_disposable = domain in disposable_set
            if is_disposable:
                continue
            
            mx_pairs = domain_mx_map.get(domain) or []
            if mx_pairs:
                if email not in resolver._smtp_cache: # Check if already in the cache
                    task = asyncio.create_task(resolver.get_smtp_status(email, mx_pairs))
                    smtp_check_tasks[email] = task

        if smtp_check_tasks:
            await asyncio.gather(*list(smtp_check_tasks.values()), return_exceptions=True)
            
        # upsert candidates into global map
        async with lock:
            for email, source, scraped_flag in final_candidates:
                if "@" not in email:
                    continue
                
                local, domain = email.rsplit("@", 1)
                domain = domain.lower()
                
                is_role = local.lower() in ROLE_LOCALPARTS
                is_disposable = domain in disposable_set
                
                mx_pairs = domain_mx_map.get(domain) or []
                mx_ok = bool(mx_pairs)
                
                # Check SMTP status from cache
                email_verified_ok = resolver._smtp_cache.get(email, False)
                if email_verified_ok:
                    smtp_verified += 1
                else:
                    smtp_unverified += 1


                sc = score_record(source, mx_ok, email_verified_ok, is_disposable, is_role, bool(scraped_flag), company_present)
                
                rec = {
                    "company": company,
                    "address": r.get("address", ""),
                    "city": r.get("city", ""),
                    "state": r.get("state", ""),
                    "zip": r.get("zip", ""),
                    "input_email": in_email,
                    "email": email,
                    "source": source,
                    "scraped": bool(scraped_flag),
                    "mx_ok": mx_ok,
                    "email_verified_ok": email_verified_ok, # NEW: Final verification status
                    "is_disposable": is_disposable,
                    "is_role": is_role,
                    "score": sc,
                    "checked_at": datetime.utcnow().isoformat() + "Z",
                }
                prev = enriched_by_email.get(email)

                def accepted(rdict):
                    if rdict is None:
                        return False
                    if rdict.get("is_disposable"):
                        return False
                    if rdict.get("is_role") and not keep_role:
                        return False
                    return (rdict.get("score", 0) > 0)

                prev_accepted = accepted(prev)
                new_accepted = accepted(rec)
                
                # Logic to keep the highest scoring record for each unique email
                if prev is None:
                    enriched_by_email[email] = rec
                    if new_accepted:
                        found_count += 1
                else:
                    if rec["score"] > prev["score"]:
                        enriched_by_email[email] = rec
                        if prev_accepted and not new_accepted:
                            found_count -= 1
                        elif not prev_accepted and new_accepted:
                            found_count += 1
                    elif rec["score"] == prev["score"]:
                        prio = {"scraped": 3, "given": 2, "generated": 1}
                        if prio.get(rec["source"], 0) > prio.get(prev.get("source", ""), 0):
                            enriched_by_email[email] = rec
                            if prev_accepted and not new_accepted:
                                found_count -= 1
                            elif not prev_accepted and new_accepted:
                                found_count += 1
                                
            processed_rows += 1

    # dispatch & heartbeat
    active: Set[asyncio.Task] = set()
    stop_event = asyncio.Event()

    async def heartbeat(interval: float = 15.0):
        while not stop_event.is_set():
            async with lock:
                LOG.info(
                    "HEARTBEAT: processed=%d active=%d candidates=%d accepted=%d SMTP_verified=%d SMTP_unverified=%d scraped_total=%d mx_cache=%d scrape_success=%d",
                    processed_rows,
                    len(active),
                    len(enriched_by_email),
                    found_count,
                    smtp_verified,
                    smtp_unverified,
                    scraped_found,
                    len(resolver._mx_cache),
                    scrape_success,
                )
            await asyncio.sleep(interval)

    hb = asyncio.create_task(heartbeat())
    
    # Start the processing run
    start_time = time.time()
    try:
        # create shared session context
        async with aiohttp.ClientSession(connector=conn, timeout=timeout, headers={"User-Agent": user_agent}) as session:
            for i, row in enumerate(raw_rows):
                if target and found_count >= int(target):
                    LOG.info("Target reached in dispatch loop: %d records accepted; stopping dispatch.", found_count)
                    break
                while len(active) >= max(1, concurrency * 2):
                    if target and found_count >= int(target):
                        break
                    await asyncio.sleep(0.05)
                if target and found_count >= int(target):
                    break
                task = asyncio.create_task(process_row(row, session))
                active.add(task)
                task.add_done_callback(lambda t, s=active: s.discard(t))

            # Wait for all tasks to complete
            while active:
                if target and found_count >= int(target):
                    LOG.info("Target reached: cancelling %d active tasks", len(active))
                    for t in list(active):
                        try:
                            t.cancel()
                        except Exception:
                            pass
                    break
                await asyncio.sleep(0.1)
    finally:
        stop_event.set()
        hb.cancel()
        if active:
            # Gather remaining tasks with exceptions suppressed
            await asyncio.gather(*list(active), return_exceptions=True)

    # finalize output
    final_list: List[Dict] = []
    for em, rec in enriched_by_email.items():
        if rec["is_disposable"]:
            continue
        if rec["is_role"] and not keep_role:
            continue
        final_list.append(rec)

    # Sort: Highest Score -> Scraped/Given -> Verified
    final_list.sort(key=lambda x: (-x["score"], not x["scraped"], not x["email_verified_ok"]))

    if target:
        final_list = final_list[: int(target)]

    out_fieldnames = [
        "company",
        "address",
        "city",
        "state",
        "zip",
        "input_email",
        "email",
        "source",
        "scraped",
        "mx_ok",
        "email_verified_ok", # NEW
        "is_disposable",
        "is_role",
        "score",
        "checked_at",
    ]
    with output_path.open("w", newline="", encoding="utf-8") as outf:
        writer = csv.DictWriter(outf, fieldnames=out_fieldnames, extrasaction="ignore")
        writer.writeheader()
        for r in final_list:
            writer.writerow(r)

    sample = final_list[:100]
    with sample_path.open("w", newline="", encoding="utf-8") as sf:
        swriter = csv.DictWriter(sf, fieldnames=out_fieldnames, extrasaction="ignore")
        swriter.writeheader()
        for r in sample:
            swriter.writerow(r)

    LOG.info(
        "Enrichment finished: output_rows=%d target=%s processed=%d candidates=%d accepted=%d SMTP_verified=%d mx_cache=%d scrape_success=%d",
        len(final_list),
        str(target),
        processed_rows,
        len(enriched_by_email),
        found_count,
        smtp_verified,
        len(resolver._mx_cache),
        scrape_success,
    )

    # Score bins (updated max score)
    bins = {"150+ (Verified)": 0, "100-149": 0, "70-99": 0, "40-69": 0, "0-39": 0}
    for r in final_list:
        sc = r["score"]
        if sc >= 150:
            bins["150+ (Verified)"] += 1
        elif sc >= 100:
            bins["100-149"] += 1
        elif sc >= 70:
            bins["70-99"] += 1
        elif sc >= 40:
            bins["40-69"] += 1
        else:
            bins["0-39"] += 1
    LOG.info("Score bins: %s", bins)

    resolver.shutdown()


# ---------------------- CLI ----------------------


def parse_args():
    p = argparse.ArgumentParser(description="Async email/domain enricher with SMTP verification.")
    # UPDATED DEFAULT INPUT FILE
    p.add_argument("--input", required=False, default="high_confidence_pi_mt_firms.csv", help="Input CSV (default: high_confidence_pi_mt_firms.csv)")
    p.add_argument("--output", required=False, default="enriched.csv", help="Output enriched CSV")
    p.add_argument("--sample", default="sample_top100.csv", help="Sample top N output CSV")
    p.add_argument("--target", type=int, default=None, help="Target number of enriched rows to produce (no default for small set)")
    p.add_argument("--concurrency", type=int, default=50, help="Async concurrency (HTTP scrapes + DNS/SMTP checks)") # Increased default concurrency for a small fast run
    p.add_argument("--http-timeout", type=float, default=6.0, help="HTTP fetch timeout seconds")
    p.add_argument("--mx-timeout", type=float, default=3.0, help="DNS MX lookup and SMTP check timeout seconds") # Reduced timeout
    p.add_argument("--user-agent", default="Mozilla/5.0 (compatible; SupioLeadEnricher/2.0)", help="User-Agent for scraping")
    p.add_argument("--keep-role", action="store_true", help="If set, keep role addresses; otherwise drop")
    p.add_argument("--disposable-file", default=None, help="Optional path to extra disposable domains (one per line)")
    
    # REMOVED BATCHING ARGUMENTS: --batch-index, --batch-size
    
    return p.parse_args()


def main():
    args = parse_args()
    logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
    
    # Updated logging to reflect removed batching args
    LOG.info("Running enrichment: input=%s output=%s concurrency=%s http_timeout=%s mx_timeout=%s",
             args.input, args.output, args.concurrency, args.http_timeout, args.mx_timeout)
             
    input_path = Path(args.input)
    output_path = Path(args.output)
    sample_path = Path(args.sample)
    disposable_path = Path(args.disposable_file) if args.disposable_file else None

    if not input_path.exists():
        LOG.error("Input file not found: %s", input_path)
        sys.exit(2)

    start = time.time()
    try:
        # The main logic is simplified as the batching arguments are gone
        asyncio.run(
            enrich(
                input_path=input_path,
                output_path=output_path,
                sample_path=sample_path,
                target=args.target,
                concurrency=args.concurrency,
                http_timeout=args.http_timeout,
                mx_timeout=args.mx_timeout,
                user_agent=args.user_agent,
                keep_role=args.keep_role,
                disposable_file=disposable_path,
            )
        )
    except KeyboardInterrupt:
        LOG.warning("Interrupted")
    except Exception as e:
        LOG.error("An unhandled error occurred: %s", e, exc_info=True)
    finally:
        LOG.info("Duration: %.1fs", time.time() - start)


if __name__ == "__main__":
    main()
