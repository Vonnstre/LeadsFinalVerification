#!/usr/bin/env python3
"""
enrich.py — fast domain-level enrichment for B2B contact lists (no SMTP probing)

Usage:
  python3 enrich.py --input companies.csv --output enriched.csv --target 10000
"""
from __future__ import annotations
import argparse
import asyncio
import csv
import logging
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import aiohttp
import dns.resolver
from bs4 import BeautifulSoup

# optional better validator
try:
    from email_validator import validate_email as ev_validate  # type: ignore
except Exception:
    ev_validate = None

LOG = logging.getLogger("enricher")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-']+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", re.I)
TLD_CANDIDATES = [".com", ".co.uk", ".uk", ".net", ".io", ".co", ".biz", ".org"]
CONTACT_PAGES = ["/", "/contact", "/contact-us", "/about", "/team"]
ROLE_LOCALPARTS = {
    "admin", "administrator", "postmaster", "hostmaster", "info", "contact", "sales", "support",
    "help", "billing", "webmaster", "noreply", "no-reply", "newsletter"
}
COMMON_DISPOSABLE = {"mailinator.com", "tempmail.com", "10minutemail.com", "yopmail.com", "dispostable.com"}
HTML_HEURISTIC_BYTES = 512


def slug_company(name: str) -> str:
    if not name:
        return ""
    s = name.lower()
    s = re.sub(r"[^0-9a-z\s]", " ", s)
    s = re.sub(r"\b(ltd|limited|co|company|inc|llc|plc)\b", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s.replace(" ", "") if s else ""


def gen_domains(company_name: str) -> List[str]:
    base = slug_company(company_name)
    out: List[str] = []
    if base:
        for t in TLD_CANDIDATES:
            out.append(base + t)
        words = re.findall(r"[a-z0-9]+", company_name.lower())
        if len(words) > 1:
            out.append("".join(words) + ".com")
            out.append(".".join(words) + ".com")
    seen = set()
    dedup = []
    for d in out:
        if d not in seen:
            dedup.append(d)
            seen.add(d)
    return dedup


def _looks_like_html(txt: str) -> bool:
    if not txt:
        return False
    sample = txt.lstrip()[:HTML_HEURISTIC_BYTES]
    return bool(re.search(r"<[a-zA-Z!\/]", sample) or ("@" in sample))


def validate_syntax(email: str) -> Tuple[bool, Optional[str]]:
    if not email or "@" not in email:
        return False, None
    try:
        if ev_validate:
            info = ev_validate(email, check_deliverability=False)
            # email_validator returns an object with .email attribute (or dict fallback)
            norm = getattr(info, "email", None) or (info["email"] if isinstance(info, dict) and "email" in info else None)
            return True, (norm or email.strip())
        m = EMAIL_RE.fullmatch(email.strip())
        return (m is not None, email.strip() if m else None)
    except Exception:
        return False, None


class MXCache:
    def __init__(self, mx_timeout: float = 6.0, threads: int = 8):
        self.mx_timeout = float(mx_timeout)
        self._cache: Dict[str, List[Tuple[int, str]]] = {}
        self._executor = ThreadPoolExecutor(max_workers=threads)

    def _resolve_sync(self, domain: str) -> List[Tuple[int, str]]:
        try:
            ans = dns.resolver.resolve(domain, "MX", lifetime=self.mx_timeout)
            pairs = sorted([(r.preference, str(r.exchange).rstrip(".")) for r in ans], key=lambda x: x[0])
            return pairs
        except Exception:
            try:
                ans = dns.resolver.resolve(domain, "A", lifetime=self.mx_timeout)
                return [(0, str(ans[0]))]
            except Exception:
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


async def scrape_domain_for_emails(session: aiohttp.ClientSession, domain: str, http_timeout: float, user_agent: str) -> Set[str]:
    found: Set[str] = set()
    headers = {"User-Agent": user_agent, "Accept": "text/html,application/xhtml+xml"}
    schemes = ["https://", "http://"]
    for scheme in schemes:
        base = scheme + domain.rstrip("/")
        for p in CONTACT_PAGES:
            url = base + p
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=http_timeout), headers=headers) as resp:
                    if resp.status != 200:
                        continue
                    txt = await resp.text(errors="replace")
                    if not _looks_like_html(txt):
                        continue
                    soup = BeautifulSoup(txt, "html.parser")
                    for a in soup.select("a[href^=mailto]"):
                        href = a.get("href", "")
                        m = re.search(r"mailto:([^?]+)", href, re.I)
                        if m:
                            found.add(m.group(1).strip().lower())
                    for e in EMAIL_RE.findall(soup.get_text(" ", strip=True)):
                        found.add(e.lower())
                    if found:
                        return found
            except asyncio.CancelledError:
                raise
            except Exception:
                continue
    return found


def score_record(source: str, mx_ok: bool, is_disposable: bool, is_role: bool, scraped: bool, company_present: bool) -> int:
    score = 0
    if source == "scraped":
        score += 60
    elif source == "given":
        score += 30
    elif source == "generated":
        score += 10
    if mx_ok:
        score += 25
    if scraped:
        score += 15
    if company_present:
        score += 5
    if is_disposable:
        score -= 50
    if is_role:
        score -= 30
    return max(0, min(100, score))


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
    # load disposable extras
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

    mx = MXCache(mx_timeout=mx_timeout, threads=max(2, min(32, concurrency)))
    conn = aiohttp.TCPConnector(limit_per_host=max(2, concurrency // 4), limit=0)
    timeout = aiohttp.ClientTimeout(total=http_timeout)

    # read input, clean & dedupe
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

    enriched_by_email: Dict[str, Dict] = {}
    lock = asyncio.Lock()
    found_count = 0  # accepted records counting (non-disposable & role filter)
    processed_rows = 0
    scraped_found = 0

    async def process_row(r: Dict[str, str]):
        nonlocal found_count, processed_rows, scraped_found
        company = r.get("company", "").strip()
        in_email = (r.get("email") or "").strip()
        candidate_emails: List[Tuple[str, str]] = []
        company_present = bool(company)

        # input email
        if in_email:
            ok, norm = validate_syntax(in_email)
            if ok and norm:
                candidate_emails.append((norm.lower(), "given"))

        # if none, generate guesses
        if not candidate_emails and company_present:
            domains = gen_domains(company)
            for d in domains:
                for lp in ("info", "contact", "sales", "hello", "admin"):
                    candidate_emails.append((f"{lp}@{d}", "generated"))

        # build domains to check
        domains_to_check: Set[str] = set()
        for em, _src in candidate_emails:
            if "@" in em:
                domains_to_check.add(em.rsplit("@", 1)[-1].lower())
        if company_present:
            for d in gen_domains(company):
                domains_to_check.add(d)

        # MX checks
        domain_mx_map: Dict[str, List[Tuple[int, str]]] = {}
        for dom in list(domains_to_check):
            try:
                mx_pairs = await mx.get_mx(dom)
            except Exception:
                mx_pairs = []
            domain_mx_map[dom] = mx_pairs
            if mx_pairs:
                # we don't increment global mx_ok_domains here for simplicity; it's computed later
                pass

        # Scrape domains in parallel (but the caller limits concurrency overall)
        scraped_emails: Set[str] = set()
        async with aiohttp.ClientSession(connector=conn, timeout=timeout) as session:
            scrape_tasks = []
            for d in domain_mx_map.keys():
                scrape_tasks.append(asyncio.create_task(scrape_domain_for_emails(session, d, http_timeout, user_agent)))
            if scrape_tasks:
                results = await asyncio.gather(*scrape_tasks, return_exceptions=True)
                for res in results:
                    if isinstance(res, set):
                        for em in res:
                            ok, norm = validate_syntax(em)
                            if ok and norm:
                                scraped_emails.add(norm.lower())
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
                # deciding acceptance for early target enforcement:
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

    # dispatch tasks in a bounded way and heartbeat
    active: Set[asyncio.Task] = set()
    stop_event = asyncio.Event()

    async def heartbeat(interval: float = 15.0):
        while not stop_event.is_set():
            async with lock:
                LOG.info("HEARTBEAT: processed=%d active=%d candidates=%d accepted=%d scraped_total=%d mx_cache=%d",
                         processed_rows, len(active), len(enriched_by_email), found_count, scraped_found, len(mx._cache))
            await asyncio.sleep(interval)

    hb = asyncio.create_task(heartbeat())

    # dispatch loop (streaming)
    try:
        for i, row in enumerate(raw_rows):
            if target and found_count >= int(target):
                LOG.info("Target reached in dispatch loop: %d records accepted; stopping dispatch.", found_count)
                break
            # keep number of active tasks bounded
            while len(active) >= max(1, concurrency * 2):
                # if target reached while waiting, break
                if target and found_count >= int(target):
                    break
                await asyncio.sleep(0.05)
            if target and found_count >= int(target):
                break
            task = asyncio.create_task(process_row(row))
            active.add(task)
            # make sure to remove from active when done
            task.add_done_callback(lambda t, s=active: s.discard(t))

        # wait for remaining tasks to complete, but if target reached cancel remaining tasks
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
            # let done callbacks remove finished tasks
    finally:
        stop_event.set()
        hb.cancel()
        # gather to ensure exceptions are surfaced (but ignore cancel exceptions)
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
        "company", "input_email", "email", "source", "scraped", "mx_ok", "is_disposable", "is_role", "score", "checked_at"
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

    # summary
    LOG.info("Enrichment finished: output_rows=%d target=%s processed=%d candidates=%d accepted=%d mx_cache=%d",
             len(final_list), str(target), processed_rows, len(enriched_by_email), found_count, len(mx._cache))

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
    mx.shutdown()


def parse_args():
    p = argparse.ArgumentParser(description="Fast email/domain enricher (no SMTP).")
    p.add_argument("--input", required=True, help="Input CSV (must contain at least CompanyName or email columns)")
    p.add_argument("--output", required=True, help="Output enriched CSV")
    p.add_argument("--sample", default="sample_top100.csv", help="Sample top N output CSV")
    p.add_argument("--target", type=int, default=10000, help="Target number of enriched rows to produce (trim final output)")
    p.add_argument("--concurrency", type=int, default=40, help="Async concurrency (scrapes + domain MX checks)")
    p.add_argument("--http-timeout", type=float, default=6.0, help="HTTP fetch timeout seconds")
    p.add_argument("--mx-timeout", type=float, default=4.0, help="DNS MX lookup timeout seconds")
    p.add_argument("--user-agent", default="Mozilla/5.0 (compatible; Enricher/1.0)", help="User-Agent for scraping")
    p.add_argument("--keep-role", action="store_true", help="If set, keep role addresses; otherwise drop")
    p.add_argument("--disposable-file", default=None, help="Optional path to extra disposable domains (one per line)")
    return p.parse_args()


def main():
    args = parse_args()
    logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
    LOG.info("Running enrichment: target=%s concurrency=%s http_timeout=%s mx_timeout=%s", args.target, args.concurrency, args.http_timeout, args.mx_timeout)
    input_path = Path(args.input)
    output_path = Path(args.output)
    sample_path = Path(args.sample)
    disposable_path = Path(args.disposable_file) if args.disposable_file else None

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


if __name__ == "__main__":
    main()
