#!/usr/bin/env python3 """ enrich.py

Improved, single-file async domain-level enricher for B2B contact lists.

Default input: ./filtered_companies.csv

Fast, free (no 3rd-party APIs), focuses on quality: reuse HTTP session, cache MX + scrapes, avoid counting A records as MX, smarter scoring, domain scrape caching, diagnostics.


Usage: python3 enrich_fixed.py --input filtered_companies.csv --output enriched.csv --sample sample_top100.csv

Notes:

This is designed to be run locally on a machine with networking access.

Tune --concurrency and --http-timeout for your environment. """ from future import annotations import argparse import asyncio import csv import logging import re import sys import time from concurrent.futures import ThreadPoolExecutor from dataclasses import dataclass from datetime import datetime from pathlib import Path from typing import Dict, List, Optional, Set, Tuple


import aiohttp import dns.resolver from bs4 import BeautifulSoup

--- Config / heuristics ---

LOG = logging.getLogger("enricher") EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-']+@[A-Za-z0-9.-]+.[A-Za-z]{2,}", re.I) TLD_CANDIDATES = [".com", ".co.uk", ".uk", ".net", ".io", ".co", ".org"] CONTACT_PAGES = ["/", "/contact", "/contact-us", "/about", "/team", "/about-us", "/people", "/staff", "/company/contact"] ROLE_LOCALPARTS = { "admin", "administrator", "postmaster", "hostmaster", "info", "contact", "sales", "support", "help", "billing", "webmaster", "noreply", "no-reply", "newsletter", "hello" } COMMON_DISPOSABLE = {"mailinator.com", "tempmail.com", "10minutemail.com", "yopmail.com", "dispostable.com"} HTML_HEURISTIC_BYTES = 2048

scoring weights (tuned for higher confidence)

WEIGHTS = { "scraped": 50, "given": 40, "generated": 5, "mx_ok": 30, "company_present": 5, "is_disposable_penalty": -80, "is_role_penalty": -30, }

--- utilities ---

def slug_company(name: str) -> str: if not name: return "" s = name.lower() s = re.sub(r"[^0-9a-z\s]", " ", s) s = re.sub(r"\b(ltd|limited|co|company|inc|llc|plc)\b", " ", s) s = re.sub(r"\s+", " ", s).strip() return s.replace(" ", "") if s else ""

def gen_domains(company_name: str) -> List[str]: base = slug_company(company_name) out: List[str] = [] if base: # prioritize .com/.co.uk/.uk for t in TLD_CANDIDATES: out.append(base + t) # also try joined/ dotted words from company name if multi-word words = re.findall(r"[a-z0-9]+", company_name.lower()) if len(words) > 1: out.append("".join(words) + ".com") out.append(".".join(words) + ".com") # dedupe seen = set() dedup = [] for d in out: if d not in seen: dedup.append(d) seen.add(d) return dedup

def _looks_like_html(txt: str) -> bool: if not txt: return False sample = txt.lstrip()[:HTML_HEURISTIC_BYTES] return bool(re.search(r"<[a-zA-Z!/]", sample) or ("@" in sample))

def validate_syntax(email: str) -> Tuple[bool, Optional[str]]: if not email or "@" not in email: return False, None m = EMAIL_RE.fullmatch(email.strip()) return (m is not None, email.strip() if m else None)

--- MX cache (no A fallback treated as MX) ---

class MXCache: def init(self, mx_timeout: float = 5.0, threads: int = 8): self.mx_timeout = float(mx_timeout) self._cache: Dict[str, List[Tuple[int, str]]] = {} self._executor = ThreadPoolExecutor(max_workers=threads)

def _resolve_sync(self, domain: str) -> List[Tuple[int, str]]:
    try:
        ans = dns.resolver.resolve(domain, "MX", lifetime=self.mx_timeout)
        pairs = sorted([(int(r.preference), str(r.exchange).rstrip(".")) for r in ans], key=lambda x: x[0])
        return pairs
    except Exception:
        # Important: do NOT treat A records as MX. False positives otherwise.
        return []

async def get_mx(self, domain: str) -> List[Tuple[int, str]]:
    d = domain.lower().strip()
    if d in self._cache:
        return self._cache[d]
    loop = asyncio.get_event_loop()
    pairs = await loop.run_in_executor(self._executor, self._resolve_sync, d)
    self._cache[d] = pairs
    return pairs

def shutdown(self):
    try:
        self._executor.shutdown(wait=False)
    except Exception:
        pass

--- HTTP scrape function (keeps focused and fast) ---

async def scrape_domain_for_emails(session: aiohttp.ClientSession, domain: str, http_timeout: float, semaphore: asyncio.Semaphore) -> Set[str]: found: Set[str] = set() headers = {"User-Agent": session.headers.get("User-Agent", "enricher/1.0"), "Accept": "text/html,application/xhtml+xml"} schemes = ["https://", "http://"]

# limit concurrent http across whole process
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
                    if "html" not in ct.lower():
                        # skip non-html quickly
                        continue
                    txt = await resp.text(errors="replace")
                    if not _looks_like_html(txt):
                        continue
                    soup = BeautifulSoup(txt, "html.parser")
                    # collect mailto links first
                    for a in soup.select("a[href^=mailto]"):
                        href = a.get("href", "")
                        m = re.search(r"mailto:([^?]+)", href, re.I)
                        if m:
                            found.add(m.group(1).strip().lower())
                    # find any emails in visible text
                    for e in EMAIL_RE.findall(soup.get_text(" ", strip=True)):
                        found.add(e.lower())
                    if found:
                        return found
            except asyncio.CancelledError:
                raise
            except Exception:
                # silent continue for speed; higher-level counters will track failures
                continue
return found

scoring

def score_record(source: str, mx_ok: bool, is_disposable: bool, is_role: bool, scraped: bool, company_present: bool) -> int: score = 0 score += WEIGHTS.get(source, 0) if mx_ok: score += WEIGHTS["mx_ok"] if scraped: score += 0  # scraped already rewarded via source if company_present: score += WEIGHTS["company_present"] if is_disposable: score += WEIGHTS["is_disposable_penalty"] if is_role: score += WEIGHTS["is_role_penalty"] return max(0, min(100, int(score)))

--- main enrichment flow ---

async def enrich( input_path: Path, output_path: Path, sample_path: Path, target: Optional[int], concurrency: int, http_timeout: float, mx_timeout: float, user_agent: str, keep_role: bool, disposable_file: Optional[Path], ): # load disposable extras disposable_set: Set[str] = set(COMMON_DISPOSABLE) if disposable_file and disposable_file.exists(): try: with disposable_file.open("r", encoding="utf-8") as f: for ln in f: s = ln.strip().lower() if s: disposable_set.add(s) except Exception: LOG.warning("failed to load disposable file; continuing with builtin list")

mx = MXCache(mx_timeout=mx_timeout, threads=max(2, min(32, concurrency)))

# shared http session & semaphore
conn = aiohttp.TCPConnector(limit=max(2, concurrency), limit_per_host=max(2, concurrency // 6))
timeout = aiohttp.ClientTimeout(total=http_timeout)
session = aiohttp.ClientSession(connector=conn, timeout=timeout, headers={"User-Agent": user_agent})
http_semaphore = asyncio.Semaphore(max(4, concurrency // 4))

# read input, clean & dedupe by company+email
raw_rows: List[Dict[str, str]] = []
seen_rows: Set[str] = set()
with input_path.open(newline="", encoding="utf-8", errors="replace") as inf:
    reader = csv.DictReader(inf)
    for row in reader:
        company = (row.get("CompanyName") or row.get("company") or "").strip()
        email = (row.get("email") or row.get("Email") or "").strip()
        if not company and not email:
            continue
        key = f"{company}||{email}"
        if key in seen_rows:
            continue
        seen_rows.add(key)
        raw_rows.append({"company": company, "email": email, **row})

LOG.info("Loaded rows: %d (after exact dedupe)", len(raw_rows))

# caches and counters
enriched_by_email: Dict[str, Dict] = {}
domain_scrape_cache: Dict[str, Set[str]] = {}
domain_mx_cache: Dict[str, List[Tuple[int, str]]] = {}
lock = asyncio.Lock()
found_count = 0
processed_rows = 0
scraped_found = 0

mx_hits = 0
mx_misses = 0
scrape_success = 0
scrape_failures = 0

async def process_row(r: Dict[str, str]):
    nonlocal found_count, processed_rows, scraped_found, mx_hits, mx_misses, scrape_success, scrape_failures
    company = r.get("company", "").strip()
    in_email = (r.get("email") or "").strip()
    candidate_emails: List[Tuple[str, str]] = []
    company_present = bool(company)

    # input email
    if in_email:
        ok, norm = validate_syntax(in_email)
        if ok and norm:
            candidate_emails.append((norm.lower(), "given"))

    # if none, generate minimal guesses (avoid role-heavy generation)
    if not candidate_emails and company_present:
        domains = gen_domains(company)
        # prefer fewer, higher-confidence domains
        for d in domains[:3]:
            # try a low-noise generation: 'contact', 'info' (role) and 'hello' but role will be penalized
            for lp in ("contact", "info", "hello"):
                candidate_emails.append((f"{lp}@{d}", "generated"))

    # build domains to check
    domains_to_check: Set[str] = set()
    for em, _src in candidate_emails:
        if "@" in em:
            domains_to_check.add(em.rsplit("@", 1)[-1].lower())
    if company_present:
        for d in gen_domains(company):
            domains_to_check.add(d)

    # MX checks (cached)
    domain_mx_map: Dict[str, List[Tuple[int, str]]] = {}
    for dom in list(domains_to_check):
        if dom in domain_mx_cache:
            mx_pairs = domain_mx_cache[dom]
        else:
            try:
                mx_pairs = await mx.get_mx(dom)
            except Exception:
                mx_pairs = []
            domain_mx_cache[dom] = mx_pairs
        domain_mx_map[dom] = mx_pairs
        if mx_pairs:
            mx_hits += 1
        else:
            mx_misses += 1

    # Scrape domain only once (cache)
    scraped_emails: Set[str] = set()
    scrape_tasks = []
    for d in domain_mx_map.keys():
        if d in domain_scrape_cache:
            cached = domain_scrape_cache[d]
            if cached:
                scraped_emails.update(cached)
        else:
            # schedule scrape
            scrape_tasks.append(asyncio.create_task(scrape_domain_for_emails(session, d, http_timeout, http_semaphore)))

    if scrape_tasks:
        results = await asyncio.gather(*scrape_tasks, return_exceptions=True)
        for i, res in enumerate(results):
            target_dom = list(domain_mx_map.keys())[i]
            if isinstance(res, set) and res:
                scraped_emails.update(res)
                domain_scrape_cache[target_dom] = res
                scrape_success += 1
            else:
                domain_scrape_cache[target_dom] = set()
                scrape_failures += 1

    if scraped_emails:
        scraped_found += len(scraped_emails)

    # assemble final candidates (scraped first)
    final_candidates: List[Tuple[str, str, bool]] = []
    for se in sorted(scraped_emails):
        final_candidates.append((se, "scraped", True))
    for em, src in candidate_emails:
        if em.lower() in scraped_emails:
            continue
        final_candidates.append((em.lower(), src, False))

    # evaluate and upsert into enriched_by_email
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

            sc = score_record(source, mx_ok, is_disposable, is_role, bool(scraped_flag), company_present)
            rec = {
                "company": company,
                "input_email": in_email,
                "email": email,
                "source": source,
                "scraped": bool(scraped_flag),
                "mx_ok": mx_ok,
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
            if prev is None:
                enriched_by_email[email] = rec
                if new_accepted:
                    found_count += 1
            else:
                # replace if better
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

# dispatcher
active: Set[asyncio.Task] = set()
stop_event = asyncio.Event()

async def heartbeat(interval: float = 15.0):
    while not stop_event.is_set():
        async with lock:
            LOG.info(
                "HEARTBEAT: processed=%d active=%d candidates=%d accepted=%d scraped_total=%d mx_cache=%d mx_hits=%d mx_misses=%d scrape_success=%d scrape_failures=%d",
                processed_rows,
                len(active),
                len(enriched_by_email),
                found_count,
                scraped_found,
                len(mx._cache),
                mx_hits,
                mx_misses,
                scrape_success,
                scrape_failures,
            )
        await asyncio.sleep(interval)

hb = asyncio.create_task(heartbeat())

try:
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
        task = asyncio.create_task(process_row(row))
        active.add(task)
        task.add_done_callback(lambda t, s=active: s.discard(t))

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
        await asyncio.gather(*list(active), return_exceptions=True)

# finalize list
final_list: List[Dict] = []
for em, rec in enriched_by_email.items():
    if rec["is_disposable"]:
        continue
    if rec["is_role"] and not keep_role:
        continue
    final_list.append(rec)

final_list.sort(key=lambda x: (-x["score"], not x["scraped"], not x["mx_ok"]))

if target:
    final_list = final_list[: int(target)]

out_fieldnames = [
    "company",
    "input_email",
    "email",
    "source",
    "scraped",
    "mx_ok",
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
    "Enrichment finished: output_rows=%d target=%s processed=%d candidates=%d accepted=%d mx_cache=%d mx_hits=%d mx_misses=%d scrape_success=%d scrape_failures=%d",
    len(final_list),
    str(target),
    processed_rows,
    len(enriched_by_email),
    found_count,
    len(mx._cache),
    mx_hits,
    mx_misses,
    scrape_success,
    scrape_failures,
)

# bins
bins = {"90+": 0, "70-89": 0, "40-69": 0, "0-39": 0}
for r in final_list:
    sc = r["score"]
    if sc >= 90:
        bins["90+"] += 1
    elif sc >= 70:
        bins["70-89"] += 1
    elif sc >= 40:
        bins["40-69"] += 1
    else:
        bins["0-39"] += 1
LOG.info("Score bins: %s", bins)

await session.close()
mx.shutdown()

--- CLI ---

def parse_args(): p = argparse.ArgumentParser(description="Improved async email/domain enricher (no SMTP).") p.add_argument("--input", required=False, default="filtered_companies.csv", help="Input CSV (must contain at least CompanyName or email columns)") p.add_argument("--output", required=False, default="enriched.csv", help="Output enriched CSV") p.add_argument("--sample", default="sample_top100.csv", help="Sample top N output CSV") p.add_argument("--target", type=int, default=None, help="Target number of enriched rows to produce (trim final output)") p.add_argument("--concurrency", type=int, default=40, help="Async concurrency (scrapes + domain MX checks)") p.add_argument("--http-timeout", type=float, default=6.0, help="HTTP fetch timeout seconds") p.add_argument("--mx-timeout", type=float, default=4.0, help="DNS MX lookup timeout seconds") p.add_argument("--user-agent", default="Mozilla/5.0 (compatible; Enricher/1.0)", help="User-Agent for scraping") p.add_argument("--keep-role", action="store_true", help="If set, keep role addresses; otherwise drop") p.add_argument("--disposable-file", default=None, help="Optional path to extra disposable domains (one per line)") return p.parse_args()

def main(): args = parse_args() logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s") LOG.info("Running enrichment: input=%s output=%s concurrency=%s http_timeout=%s mx_timeout=%s", args.input, args.output, args.concurrency, args.http_timeout, args.mx_timeout) input_path = Path(args.input) output_path = Path(args.output) sample_path = Path(args.sample) disposable_path = Path(args.disposable_file) if args.disposable_file else None

if not input_path.exists():
    LOG.error("Input file not found: %s", input_path)
    sys.exit(2)

start = time.time()
try:
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
finally:
    LOG.info("Duration: %.1fs", time.time() - start)

if name == "main": main()

