#!/usr/bin/env python3
"""
scripts/enrich.py — production-grade, proof-backed email enricher

Implements:
 1) STARTTLS upgrade when advertised
 2) 4xx retries with backoff and retry scheduler
 3) Confidence scoring (_score)
 4) Full SMTP transcript capture saved per-check
 5) Configurable MAIL FROM list (rotation)
 6) Alternate ports (25,587,465) and implicit TLS attempt
 7) Retry queue for 4xx responses
 8) Tight rate-limiting: per-host semaphores + per-MX minimum interval + global cap
 9) Scoring & flags in CSV (_score, _smtp_transcript_path)
10) --skip-smtp fallback (scrape + MX heuristics)

Usage example:
  python3 scripts/enrich.py --input filtered_companies.csv --output enriched_verified.csv \
      --concurrency 30 --smtp-timeout 8 --mx-timeout 6 --mail-from-list mailfroms.txt --ports 25,587,465

Notes:
 - Run this from a machine with SMTP egress (port 25) or use --skip-smtp for CI (less accurate).
 - Transcripts are saved to ./transcripts/ by default and the CSV will include _smtp_transcript_path.
"""

from __future__ import annotations
import argparse
import asyncio
import csv
import io
import logging
import os
import random
import re
import smtplib
import ssl
import string
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stderr, redirect_stdout, contextmanager
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import aiohttp
import dns.resolver
from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning

LOG = logging.getLogger("enricher")

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-']+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", re.I)
TLD_CANDIDATES = [".com", ".co.uk", ".uk", ".net", ".io", ".co", ".biz", ".org"]
CONTACT_PAGES = ["/", "/contact", "/contact-us", "/about", "/about-us", "/team", "/staff", "/people", "/privacy"]
ROLE_LOCALPARTS = {"admin", "administrator", "postmaster", "hostmaster", "info", "contact", "sales", "support", "help", "billing", "webmaster", "noreply", "no-reply", "newsletter"}
COMMON_DISPOSABLE = {"mailinator.com", "tempmail.com", "10minutemail.com", "yopmail.com", "dispostable.com"}
HTML_HEURISTIC_BYTES = 512
TRANSCRIPTS_DIR = Path("transcripts")
TRANSCRIPTS_DIR.mkdir(exist_ok=True)

# Optional email-validator for better syntax checks
try:
    from email_validator import validate_email as ev_validate, EmailNotValidError
except Exception:
    ev_validate = None
    EmailNotValidError = Exception

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
    dedup: List[str] = []
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

@contextmanager
def _suppress_bs4_warning():
    import warnings
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)
        yield

def is_role_local(local: str) -> bool:
    return local.lower() in ROLE_LOCALPARTS

def is_disposable_domain(domain: str, extras: Optional[Set[str]] = None) -> bool:
    s = set(COMMON_DISPOSABLE)
    if extras:
        s |= extras
    return domain.lower() in s

def random_localpart() -> str:
    return "probe" + "".join(random.choices(string.ascii_lowercase + string.digits, k=8))

# MX cache with threaded resolver
class MXCache:
    def __init__(self, mx_timeout: float = 6.0, threads: int = 8):
        self.mx_timeout = float(mx_timeout)
        self._cache: Dict[str, List[Tuple[int, str]]] = {}
        self._executor = ThreadPoolExecutor(max_workers=threads)

    def _resolve_mx_sync(self, domain: str) -> List[Tuple[int, str]]:
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
        if domain in self._cache:
            return self._cache[domain]
        loop = asyncio.get_event_loop()
        pairs = await loop.run_in_executor(self._executor, self._resolve_mx_sync, domain)
        self._cache[domain] = pairs
        return pairs

    def shutdown(self):
        try:
            self._executor.shutdown(wait=False)
        except Exception:
            pass

# Blocking SMTP prober executed in threadpool (uses smtplib to support STARTTLS/implicit TLS reliably)
class SMTPProbeResult:
    def __init__(self, code: Optional[int], message: Optional[str], transcript: str, port: int, used_tls: bool):
        self.code = code
        self.message = message
        self.transcript = transcript
        self.port = port
        self.used_tls = used_tls

class SMTPProber:
    def __init__(self, smtp_timeout: float = 8.0, threads: int = 20):
        self.smtp_timeout = float(smtp_timeout)
        self._executor = ThreadPoolExecutor(max_workers=threads)

    def _probe_sync(self, host: str, port: int, mail_from: str, rcpt_to: str, try_starttls: bool, implicit_tls: bool, timeout: float) -> SMTPProbeResult:
        buf = io.StringIO()
        used_tls = False
        code = None
        message = ""
        context = ssl.create_default_context()
        try:
            if implicit_tls:
                smtp = smtplib.SMTP_SSL(host=host, port=port, timeout=timeout, context=context)
            else:
                smtp = smtplib.SMTP(host=host, port=port, timeout=timeout)
            smtp.set_debuglevel(1)
            with redirect_stdout(buf), redirect_stderr(buf):
                try:
                    smtp.ehlo()
                except Exception:
                    pass
                try:
                    if try_starttls and (not implicit_tls):
                        if smtp.has_extn('starttls'):
                            try:
                                smtp.starttls(context=context)
                                used_tls = True
                                smtp.ehlo()
                            except Exception:
                                pass
                except Exception:
                    pass
                try:
                    smtp.docmd("MAIL FROM", "<%s>" % mail_from)
                except Exception:
                    pass
                try:
                    rcpt_code, rcpt_msg = smtp.docmd("RCPT TO", "<%s>" % rcpt_to)
                    code = int(rcpt_code) if isinstance(rcpt_code, int) or (rcpt_code and str(rcpt_code).isdigit()) else None
                    message = rcpt_msg.decode() if isinstance(rcpt_msg, bytes) else str(rcpt_msg)
                except Exception as e:
                    message = f"rcpt-except:{e}"
                try:
                    smtp.quit()
                except Exception:
                    try:
                        smtp.close()
                    except Exception:
                        pass
        except Exception as e:
            buf.write(f"connect-error:{e}\n")
        transcript = buf.getvalue()
        return SMTPProbeResult(code, message, transcript, port, used_tls)

    async def probe(self, host: str, port: int, mail_from: str, rcpt_to: str, try_starttls: bool, implicit_tls: bool) -> SMTPProbeResult:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self._executor, self._probe_sync, host, port, mail_from, rcpt_to, try_starttls, implicit_tls, self.smtp_timeout)

    def shutdown(self):
        try:
            self._executor.shutdown(wait=False)
        except Exception:
            pass

# Verifier orchestrates MX + SMTP probes, caching, rate-limiting, catch-all detection
class Verifier:
    def __init__(self, args):
        self.args = args
        self.mx_cache = MXCache(mx_timeout=args.mx_timeout, threads=8)
        self.prober = SMTPProber(smtp_timeout=args.smtp_timeout, threads=32)
        self.global_semaphore = asyncio.Semaphore(args.global_limit)
        self.per_host_semaphores: Dict[str, asyncio.Semaphore] = {}
        self.per_host_min_interval: Dict[str, float] = {}
        self.last_probe_at: Dict[str, float] = {}
        self.catch_all_cache: Dict[str, bool] = {}
        self.mail_froms = self._load_mail_froms(args.mail_from_list)
        self.mail_idx = 0
        self.disposable_set: Set[str] = set()
        if args.disposable_file:
            try:
                with open(args.disposable_file, "r", encoding="utf-8") as f:
                    for ln in f:
                        self.disposable_set.add(ln.strip().lower())
            except Exception:
                LOG.warning("Could not load disposable list; proceeding with built-in list")

    def _load_mail_froms(self, path: Optional[str]) -> List[str]:
        if not path:
            return [self.args.mail_from]
        p = Path(path)
        if not p.exists():
            return [self.args.mail_from]
        out = []
        with open(p, encoding="utf-8") as f:
            for ln in f:
                s = ln.strip()
                if s:
                    out.append(s)
        return out or [self.args.mail_from]

    def _next_mail_from(self) -> str:
        if not self.mail_froms:
            return self.args.mail_from
        idx = self.mail_idx % len(self.mail_froms)
        self.mail_idx += 1
        return self.mail_froms[idx]

    def _get_host_sem(self, host: str) -> asyncio.Semaphore:
        if host not in self.per_host_semaphores:
            self.per_host_semaphores[host] = asyncio.Semaphore(self.args.per_host_limit)
            self.per_host_min_interval[host] = self.args.per_host_interval
            self.last_probe_at[host] = 0.0
        return self.per_host_semaphores[host]

    async def _respect_host_interval(self, host: str):
        min_int = self.per_host_min_interval.get(host, self.args.per_host_interval)
        last = self.last_probe_at.get(host, 0.0)
        now = time.time()
        wait = min_int - (now - last)
        if wait > 0:
            await asyncio.sleep(wait)

    async def _probe_mx_host(self, host: str, ports: List[int], mail_from: str, email: str) -> Optional[SMTPProbeResult]:
        sem = self._get_host_sem(host)
        async with self.global_semaphore:
            async with sem:
                await self._respect_host_interval(host)
                for port in ports:
                    implicit_tls = (port == 465)
                    try_starttls = (not implicit_tls)
                    res = await self.prober.probe(host, port, mail_from, email, try_starttls, implicit_tls)
                    self.last_probe_at[host] = time.time()
                    if res.code is None and "connect-error" in (res.message or ""):
                        continue
                    return res
        return None

    async def verify_address(self, email: str, mx_pairs: List[Tuple[int, str]]) -> Dict:
        if not mx_pairs:
            return {"status": "no_mx", "_score": 0}
        domain = email.rsplit("@", 1)[-1]
        if domain not in self.catch_all_cache:
            pref, host = mx_pairs[0]
            mail_from = self._next_mail_from()
            rand = random_localpart()
            rand_addr = f"{rand}@{domain}"
            probe = await self._probe_mx_host(host, self.args.ports, mail_from, rand_addr)
            catch = False
            if probe and probe.code is not None and 200 <= int(probe.code) < 300:
                catch = True
            self.catch_all_cache[domain] = catch
        catch_flag = self.catch_all_cache.get(domain, False)
        for pref, host in mx_pairs:
            mail_from = self._next_mail_from()
            probe = await self._probe_mx_host(host, self.args.ports, mail_from, email)
            if probe is None:
                continue
            ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
            fn = TRANSCRIPTS_DIR / f"{domain}_{email.replace('@','%40')}_{int(time.time())}_{probe.port}.txt"
            try:
                with open(fn, "w", encoding="utf-8") as tf:
                    tf.write(f"transcript_time: {ts}\nused_tls: {probe.used_tls}\nport: {probe.port}\n")
                    tf.write(probe.transcript or "")
            except Exception:
                pass
            code = probe.code
            msg = probe.message
            if code is None:
                status = "no_response"
                score = 20
            elif 200 <= int(code) < 300:
                status = "valid_catch" if catch_flag else "valid"
                score = 90 if not catch_flag else 65
            elif 400 <= int(code) < 500:
                status = "temporary"
                score = 40
            elif 500 <= int(code) < 600:
                status = "invalid"
                score = 0
            else:
                status = "unknown"
                score = 30
            return {"status": status, "_smtp_code": code, "_smtp_message": msg, "_catch_all": catch_flag, "_score": score, "_smtp_transcript_path": str(fn)}
        return {"status": "no_response", "_score": 10}

# Scraping fallback
async def scrape_for_emails(session: aiohttp.ClientSession, domain: str, http_timeout: float) -> Set[str]:
    found: Set[str] = set()
    schemes = ["https://", "http://"]
    for scheme in schemes:
        base = scheme + domain.rstrip("/")
        for p in ["/", "/contact", "/contact-us", "/about", "/team"]:
            url = base + p
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=http_timeout)) as resp:
                    if resp.status != 200:
                        continue
                    txt = await resp.text(errors="replace")
                    if not _looks_like_html(txt):
                        continue
                    with _suppress_bs4_warning():
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

def validate_syntax(email: str) -> Tuple[bool, Optional[str]]:
    if not email or "@" not in email:
        return False, None
    try:
        if ev_validate:
            info = ev_validate(email, check_deliverability=False)
            return True, info["email"]
        m = EMAIL_RE.fullmatch(email.strip())
        return (m is not None, email.strip() if m else None)
    except Exception:
        return False, None

# Enricher pipeline with retry scheduler for temporary (4xx) results
class Enricher:
    def __init__(self, args):
        self.args = args
        self.verifier = Verifier(args)
        self.http_timeout = args.http_timeout
        self.retries_queue: List[Tuple[float, Dict]] = []  # (run_at, payload)
        self.retry_lock = asyncio.Lock()

    async def _retry_scheduler(self, main_queue: asyncio.Queue, stop_event: asyncio.Event):
        while not stop_event.is_set():
            now = time.time()
            to_move = []
            async with self.retry_lock:
                i = 0
                while i < len(self.retries_queue):
                    run_at, payload = self.retries_queue[i]
                    if run_at <= now:
                        to_move.append(payload)
                        self.retries_queue.pop(i)
                    else:
                        i += 1
            for p in to_move:
                try:
                    await main_queue.put(p)
                except Exception:
                    pass
            await asyncio.sleep(1.0)

    async def _process_row(self, row: Dict[str, str], session: aiohttp.ClientSession) -> Optional[Dict[str, str]]:
        candidate = (row.get("email") or row.get("Email") or "").strip()
        company = (row.get("CompanyName") or row.get("company") or "").strip()
        candidates: List[str] = []
        if candidate:
            candidates.append(candidate)
        else:
            domains = gen_domains(company) if company else []
            for d in domains:
                for lp in ("info", "contact", "sales", "hello", "admin"):
                    candidates.append(f"{lp}@{d}")
        if not candidates:
            return None

        for cand in candidates:
            ok, norm = validate_syntax(cand)
            ts = int(time.time())
            if not ok:
                continue
            email_norm = norm or cand
            local, domain = email_norm.rsplit("@", 1)
            is_role = is_role_local(local)
            is_disp = is_disposable_domain(domain, self.verifier.disposable_set)

            if self.args.skip_smtp:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.http_timeout)) as session_local:
                    emails = await scrape_for_emails(session_local, domain, self.http_timeout)
                    if emails:
                        first = sorted(emails)[0]
                        enriched = dict(row)
                        enriched.update({"_found_email": first, "_verification_status": "found_via_scrape", "_smtp_code": "", "_smtp_message": "", "_catch_all": False, "_is_disposable": is_disp, "_is_role": is_role, "_score": 50, "_checked_at": ts})
                        return enriched
                    else:
                        enriched = dict(row)
                        enriched.update({"_found_email": email_norm, "_verification_status": "no_smtp_no_scrape", "_smtp_code": "", "_smtp_message": "", "_catch_all": False, "_is_disposable": is_disp, "_is_role": is_role, "_score": 10, "_checked_at": ts})
                        return enriched

            mx_pairs = await self.verifier.mx_cache.get_mx(domain)
            if not mx_pairs:
                enriched = dict(row)
                enriched.update({"_found_email": email_norm, "_verification_status": "no_mx", "_smtp_code": "", "_smtp_message": "", "_catch_all": False, "_is_disposable": is_disp, "_is_role": is_role, "_score": 0, "_checked_at": ts})
                return enriched

            result = await self.verifier.verify_address(email_norm, mx_pairs)
            status = result.get("status")
            score = result.get("_score", 0)
            transcript_path = result.get("_smtp_transcript_path", "")

            if status == "temporary":
                retries = int(row.get("_retries", 0))
                if retries < self.args.temporary_retries:
                    delay = self.args.temporary_backoff * (2 ** retries)
                    payload = dict(row)
                    payload["_retries"] = retries + 1
                    run_at = time.time() + delay
                    async with self.retry_lock:
                        self.retries_queue.append((run_at, payload))
                    LOG.info("Scheduled retry for %s in %.1fs (attempt %d)", email_norm, delay, retries + 1)
                    continue
                else:
                    enriched = dict(row)
                    enriched.update({"_found_email": email_norm, "_verification_status": "unknown_after_retries", "_smtp_code": result.get("_smtp_code", ""), "_smtp_message": result.get("_smtp_message", ""), "_catch_all": result.get("_catch_all", False), "_is_disposable": is_disp, "_is_role": is_role, "_score": result.get("_score", 40), "_smtp_transcript_path": transcript_path, "_checked_at": ts})
                    return enriched

            enriched = dict(row)
            enriched.update({"_found_email": email_norm, "_verification_status": status, "_smtp_code": result.get("_smtp_code", ""), "_smtp_message": result.get("_smtp_message", ""), "_catch_all": result.get("_catch_all", False), "_is_disposable": is_disp, "_is_role": is_role, "_score": score, "_smtp_transcript_path": transcript_path, "_checked_at": ts})
            return enriched
        return None

    async def run(self):
        in_path = Path(self.args.input)
        if not in_path.exists():
            LOG.error("Input not found: %s", in_path)
            return 2
        out_path = Path(self.args.output)
        os.makedirs(out_path.parent, exist_ok=True)

        timeout = aiohttp.ClientTimeout(total=self.http_timeout)
        headers = {"User-Agent": self.args.user_agent, "Accept": "text/html,application/xhtml+xml"}
        conn = aiohttp.TCPConnector(limit_per_host=max(2, self.args.concurrency // 4), limit=0)

        async with aiohttp.ClientSession(connector=conn, timeout=timeout, headers=headers) as session:
            with open(in_path, newline="", encoding="utf-8", errors="replace") as inf:
                reader = csv.DictReader(inf)
                in_fields = reader.fieldnames or []
                out_fields = list(in_fields) + ["_found_email", "_verification_status", "_smtp_code", "_smtp_message", "_catch_all", "_is_disposable", "_is_role", "_score", "_smtp_transcript_path", "_checked_at"]
                with open(out_path, "w", newline="", encoding="utf-8") as outf:
                    writer = csv.DictWriter(outf, fieldnames=out_fields, extrasaction="ignore")
                    writer.writeheader()
                    q = asyncio.Queue(maxsize=10000)
                    stop_ev = asyncio.Event()
                    concurrency = max(2, min(self.args.concurrency, 200))
                    workers = [asyncio.create_task(self._worker_loop(q, writer, session, stop_ev)) for _ in range(concurrency)]
                    sched = asyncio.create_task(self._retry_scheduler(q, stop_ev))

                    pushed = 0
                    try:
                        for row in reader:
                            if stop_ev.is_set():
                                break
                            await q.put(row)
                            pushed += 1
                            if pushed % 500 == 0:
                                LOG.info("Queued rows: %d", pushed)
                        while not q.empty() or (self.retries_queue and not stop_ev.is_set()):
                            await asyncio.sleep(0.5)
                    finally:
                        stop_ev.set()
                        await asyncio.gather(*workers, return_exceptions=True)
                        sched.cancel()

        try:
            self.verifier.mx_cache.shutdown()
            self.verifier.prober.shutdown()
        except Exception:
            pass
        LOG.info("Finished. Approx queued rows: %d", pushed)
        return 0

    async def _worker_loop(self, q: asyncio.Queue, writer: csv.DictWriter, session: aiohttp.ClientSession, stop_ev: asyncio.Event):
        while not stop_ev.is_set():
            try:
                row = await asyncio.wait_for(q.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            try:
                enriched = await self._process_row(row, session)
                if enriched:
                    writer.writerow(enriched)
            except Exception:
                LOG.exception("Worker error")
            finally:
                try:
                    q.task_done()
                except Exception:
                    pass

def parse_args():
    p = argparse.ArgumentParser(description="Enricher — MX + SMTP + STARTTLS + retries + scoring")
    p.add_argument("--input", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--concurrency", type=int, default=30)
    p.add_argument("--smtp-timeout", type=float, default=8.0)
    p.add_argument("--mx-timeout", type=float, default=6.0)
    p.add_argument("--http-timeout", type=float, default=8.0)
    p.add_argument("--mail-from", default="verifier@example.com")
    p.add_argument("--mail-from-list", default=None, help="Path to file with one MAIL FROM per line (rotated)")
    p.add_argument("--user-agent", default="Mozilla/5.0 (compatible; Enricher/1.0)")
    p.add_argument("--disposable-file", default=None)
    p.add_argument("--skip-smtp", action="store_true", help="Skip SMTP probes (useful if port 25 blocked)")
    p.add_argument("--ports", default="25", help="Comma-separated ports to try (e.g. 25,587,465)")
    p.add_argument("--per-host-limit", type=int, default=2)
    p.add_argument("--per-host-interval", type=float, default=1.0, help="Minimum seconds between probes to same host")
    p.add_argument("--global-limit", type=int, default=50)
    p.add_argument("--temporary-retries", type=int, default=2, help="Retries for 4xx temporary codes")
    p.add_argument("--temporary-backoff", type=float, default=30.0, help="Base backoff seconds for temporary retries; exponential")
    return p.parse_args()

def main():
    args = parse_args()
    args.ports = [int(x.strip()) for x in args.ports.split(",") if x.strip().isdigit()]
    args.per_host_limit = getattr(args, "per_host_limit", 2)
    args.per_host_interval = getattr(args, "per_host_interval", 1.0)
    args.global_limit = getattr(args, "global_limit", 50)
    args.temporary_retries = getattr(args, "temporary_retries", 2)
    args.temporary_backoff = getattr(args, "temporary_backoff", 30.0)

    logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
    LOG.info("Starting enricher")
    enr = Enricher(args)
    try:
        res = asyncio.run(enr.run())
        sys.exit(res or 0)
    except KeyboardInterrupt:
        LOG.warning("Interrupted")
        sys.exit(2)

if __name__ == "__main__":
    main()
