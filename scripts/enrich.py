#!/usr/bin/env python3
"""
scripts/enrich.py — compact, robust email enricher

Features:
 - Domain generation from company name
 - MX lookup (cached) using dnspython in a small threadpool
 - Blocking SMTP probes via smtplib in a threadpool (EHLO, STARTTLS if offered, MAIL FROM, RCPT TO)
 - Try ports (25, 587, 465) where 465 => implicit TLS
 - Per-MX-host semaphore + per-host minimum interval + global concurrency cap
 - Retry scheduler for temporary 4xx responses (exponential backoff)
 - Save SMTP transcript per probe under ./transcripts/
 - Scraping fallback if --skip-smtp or SMTP unavailable
 - Streaming CSV input/output; stops after --target enriched rows written
 - Minimal external dependencies
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
import signal
import smtplib
import ssl
import string
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import aiohttp
import dns.resolver
import warnings
from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning

# ---------------- config ----------------
LOG = logging.getLogger("enricher")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-']+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", re.I)
TLD_CANDIDATES = [".com", ".co.uk", ".uk", ".net", ".io", ".co", ".biz", ".org"]
CONTACT_PAGES = ["/", "/contact", "/contact-us", "/about", "/about-us", "/team", "/people"]
ROLE_LOCALPARTS = {"admin", "info", "contact", "sales", "support", "billing", "webmaster", "postmaster"}
COMMON_DISPOSABLE = {"mailinator.com", "tempmail.com", "yopmail.com"}
HTML_HEURISTIC_BYTES = 512
TRANSCRIPTS_DIR = Path("transcripts")
TRANSCRIPTS_DIR.mkdir(parents=True, exist_ok=True)

# optional: email-validator for stronger syntax checks
try:
    from email_validator import validate_email as ev_validate  # type: ignore
except Exception:
    ev_validate = None

# ---------------- small helpers ----------------
def slug_company(name: str) -> str:
    if not name:
        return ""
    s = name.lower()
    s = re.sub(r"[^0-9a-z\s]", " ", s)
    s = re.sub(r"\b(ltd|limited|co|company|inc|llc|plc)\b", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s.replace(" ", "") if s else ""

def gen_domains(company: str) -> List[str]:
    base = slug_company(company)
    out: List[str] = []
    if base:
        for t in TLD_CANDIDATES:
            out.append(base + t)
        words = re.findall(r"[a-z0-9]+", company.lower())
        if len(words) > 1:
            out.append("".join(words) + ".com")
            out.append(".".join(words) + ".com")
    seen = set()
    dedup = []
    for d in out:
        if d not in seen:
            dedup.append(d); seen.add(d)
    return dedup

def _looks_like_html(txt: str) -> bool:
    if not txt:
        return False
    sample = txt.lstrip()[:HTML_HEURISTIC_BYTES]
    return bool(re.search(r"<[a-zA-Z!\/]", sample) or ("@" in sample))

def random_localpart() -> str:
    return "probe" + "".join(random.choices(string.ascii_lowercase + string.digits, k=8))

@staticmethod
def _suppress_bs4():
    return warnings.catch_warnings()

# ---------------- MX cache (threaded) ----------------
class MXCache:
    def __init__(self, timeout: float = 6.0, threads: int = 6):
        self.timeout = float(timeout)
        self._cache: Dict[str, List[Tuple[int, str]]] = {}
        self._executor = ThreadPoolExecutor(max_workers=threads)

    def _resolve_sync(self, domain: str) -> List[Tuple[int, str]]:
        try:
            ans = dns.resolver.resolve(domain, "MX", lifetime=self.timeout)
            pairs = sorted([(r.preference, str(r.exchange).rstrip(".")) for r in ans], key=lambda x: x[0])
            return pairs
        except Exception:
            try:
                ans = dns.resolver.resolve(domain, "A", lifetime=self.timeout)
                return [(0, str(ans[0]))]
            except Exception:
                return []

    async def get_mx(self, domain: str) -> List[Tuple[int, str]]:
        if domain in self._cache:
            return self._cache[domain]
        loop = asyncio.get_event_loop()
        pairs = await loop.run_in_executor(self._executor, self._resolve_sync, domain)
        self._cache[domain] = pairs
        return pairs

    def shutdown(self):
        try:
            self._executor.shutdown(wait=False)
        except Exception:
            pass

# ---------------- SMTP prober (blocking in threadpool, smtplib) ----------------
class SMTPProbeResult:
    def __init__(self, code: Optional[int], message: Optional[str], transcript: str, port: int, used_tls: bool):
        self.code = code
        self.message = message
        self.transcript = transcript
        self.port = port
        self.used_tls = used_tls

class SMTPProber:
    def __init__(self, timeout: float = 8.0, threads: int = 12):
        self.timeout = float(timeout)
        self._executor = ThreadPoolExecutor(max_workers=threads)

    def _probe_sync(self, host: str, port: int, mail_from: str, rcpt_to: str, try_starttls: bool, implicit_tls: bool, timeout: float) -> SMTPProbeResult:
        buf = io.StringIO()
        used_tls = False
        code = None
        message = ""
        ctx = ssl.create_default_context()
        try:
            if implicit_tls:
                smtp = smtplib.SMTP_SSL(host=host, port=port, timeout=timeout, context=ctx)
            else:
                smtp = smtplib.SMTP(host=host, port=port, timeout=timeout)
            smtp.set_debuglevel(1)
            with redirect_stdout(buf), redirect_stderr(buf):
                try:
                    smtp.ehlo()
                except Exception:
                    pass
                if try_starttls and (not implicit_tls):
                    try:
                        if smtp.has_extn("starttls"):
                            smtp.starttls(context=ctx)
                            used_tls = True
                            smtp.ehlo()
                    except Exception:
                        # ignore failed STARTTLS and continue
                        pass
                try:
                    smtp.docmd("MAIL FROM", "<%s>" % mail_from)
                except Exception:
                    pass
                try:
                    rcpt_code, rcpt_msg = smtp.docmd("RCPT TO", "<%s>" % rcpt_to)
                    code = int(rcpt_code) if (rcpt_code and str(rcpt_code).isdigit()) else None
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
        return SMTPProbeResult(code, message, buf.getvalue(), port, used_tls)

    async def probe(self, host: str, port: int, mail_from: str, rcpt_to: str, try_starttls: bool, implicit_tls: bool) -> SMTPProbeResult:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self._executor, self._probe_sync, host, port, mail_from, rcpt_to, try_starttls, implicit_tls, self.timeout)

    def shutdown(self):
        try:
            self._executor.shutdown(wait=False)
        except Exception:
            pass

# ---------------- Verifier orchestrator ----------------
class Verifier:
    def __init__(self, args):
        self.args = args
        self.mx = MXCache(timeout=args.mx_timeout, threads=max(2, args.concurrency // 4))
        self.prober = SMTPProber(timeout=args.smtp_timeout, threads=max(4, args.concurrency // 2))
        self.global_sem = asyncio.Semaphore(args.global_limit)
        self.per_host_sems: Dict[str, asyncio.Semaphore] = {}
        self.per_host_interval: Dict[str, float] = {}
        self.last_probe_at: Dict[str, float] = {}
        self.catch_all: Dict[str, bool] = {}
        self.mail_froms = self._load_mail_froms(args.mail_from_list, args.mail_from)
        self.mail_idx = 0
        self.disposable: Set[str] = set()
        if args.disposable_file:
            try:
                with open(args.disposable_file, "r", encoding="utf-8") as f:
                    for ln in f:
                        self.disposable.add(ln.strip().lower())
            except Exception:
                LOG.warning("couldn't load disposable list")

    def _load_mail_froms(self, path: Optional[str], default: str) -> List[str]:
        if not path:
            return [default]
        p = Path(path)
        if not p.exists():
            return [default]
        out = []
        with open(p, encoding="utf-8") as f:
            for ln in f:
                s = ln.strip()
                if s:
                    out.append(s)
        return out or [default]

    def _next_mail_from(self) -> str:
        if not self.mail_froms:
            return self.args.mail_from
        idx = self.mail_idx % len(self.mail_froms)
        self.mail_idx += 1
        return self.mail_froms[idx]

    def _host_sem(self, host: str) -> asyncio.Semaphore:
        if host not in self.per_host_sems:
            self.per_host_sems[host] = asyncio.Semaphore(self.args.per_host_limit)
            self.per_host_interval[host] = self.args.per_host_interval
            self.last_probe_at[host] = 0.0
        return self.per_host_sems[host]

    async def _respect_interval(self, host: str):
        last = self.last_probe_at.get(host, 0.0)
        wait = self.per_host_interval.get(host, self.args.per_host_interval) - (time.time() - last)
        if wait > 0:
            await asyncio.sleep(wait)

    async def _probe_host(self, host: str, ports: List[int], mail_from: str, email: str) -> Optional[SMTPProbeResult]:
        sem = self._host_sem(host)
        async with self.global_sem:
            async with sem:
                await self._respect_interval(host)
                for port in ports:
                    implicit = (port == 465)
                    try_starttls = not implicit
                    res = await self.prober.probe(host, port, mail_from, email, try_starttls, implicit)
                    self.last_probe_at[host] = time.time()
                    if res.code is None and ("connect-error" in (res.message or "")):
                        continue
                    return res
        return None

    async def verify(self, email: str, mx_pairs: List[Tuple[int, str]]) -> Dict:
        if not mx_pairs:
            return {"status": "no_mx", "_score": 0}
        domain = email.split("@", 1)[1]
        if domain not in self.catch_all:
            pref, host = mx_pairs[0]
            rand = random_localpart()
            probe = await self._probe_host(host, self.args.ports, self._next_mail_from(), f"{rand}@{domain}")
            is_catch = (probe and probe.code is not None and 200 <= probe.code < 300)
            self.catch_all[domain] = bool(is_catch)
        catch = self.catch_all.get(domain, False)
        for pref, host in mx_pairs:
            probe = await self._probe_host(host, self.args.ports, self._next_mail_from(), email)
            if not probe:
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
                return {"status": "no_response", "_score": 20, "_smtp_code": None, "_smtp_message": msg, "_catch_all": catch, "_smtp_transcript_path": str(fn)}
            if 200 <= code < 300:
                status = "valid_catch" if catch else "valid"
                score = 90 if not catch else 65
            elif 400 <= code < 500:
                status, score = "temporary", 40
            elif 500 <= code < 600:
                status, score = "invalid", 0
            else:
                status, score = "unknown", 30
            return {"status": status, "_score": score, "_smtp_code": code, "_smtp_message": msg, "_catch_all": catch, "_smtp_transcript_path": str(fn)}
        return {"status": "no_response", "_score": 10}

# ---------------- scraping fallback ----------------
async def scrape_for_emails(session: aiohttp.ClientSession, domain: str, http_timeout: float) -> Set[str]:
    found: Set[str] = set()
    for scheme in ("https://", "http://"):
        base = scheme + domain.rstrip("/")
        for p in CONTACT_PAGES:
            url = base + p
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=http_timeout)) as resp:
                    if resp.status != 200:
                        continue
                    txt = await resp.text(errors="replace")
                    if not _looks_like_html(txt):
                        continue
                    with warnings.catch_warnings():
                        warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)
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
            except Exception:
                continue
    return found

# ---------------- syntax validation ----------------
def validate_syntax(email: str) -> Tuple[bool, Optional[str]]:
    if not email or "@" not in email:
        return False, None
    try:
        if ev_validate:
            v = ev_validate(email, check_deliverability=False)
            return True, v["email"]
        m = EMAIL_RE.fullmatch(email.strip())
        return (m is not None, email.strip() if m else None)
    except Exception:
        return False, None

# ---------------- enricher pipeline ----------------
class Enricher:
    def __init__(self, args):
        self.args = args
        self.verifier = Verifier(args)
        self.http_timeout = args.http_timeout
        self.retries: List[Tuple[float, Dict]] = []  # (run_at, payload)
        self.retries_lock = asyncio.Lock()
        self.enriched_written = 0
        self.enriched_lock = asyncio.Lock()

    async def retry_scheduler(self, main_q: asyncio.Queue, stop_ev: asyncio.Event):
        while not stop_ev.is_set():
            now = time.time()
            due = []
            async with self.retries_lock:
                i = 0
                while i < len(self.retries):
                    if self.retries[i][0] <= now:
                        due.append(self.retries[i][1])
                        self.retries.pop(i)
                    else:
                        i += 1
            for item in due:
                try:
                    await main_q.put(item)
                except Exception:
                    pass
            await asyncio.sleep(1.0)

    async def process_row(self, row: Dict[str, str], session: aiohttp.ClientSession) -> Optional[Dict[str, str]]:
        candidate = (row.get("email") or row.get("Email") or "").strip()
        company = (row.get("CompanyName") or row.get("company") or "").strip()
        candidates: List[str] = []
        if candidate:
            candidates.append(candidate)
        else:
            for d in gen_domains(company):
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
            is_role = local.lower() in ROLE_LOCALPARTS
            is_disp = domain.lower() in COMMON_DISPOSABLE

            if self.args.skip_smtp:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.http_timeout)) as s:
                    found = await scrape_for_emails(s, domain, self.http_timeout)
                    if found:
                        first = sorted(found)[0]
                        return {**row, "_found_email": first, "_verification_status": "found_via_scrape", "_score": 50, "_checked_at": ts}
                    return {**row, "_found_email": email_norm, "_verification_status": "no_smtp_no_scrape", "_score": 10, "_checked_at": ts}

            mx_pairs = await self.verifier.mx.get_mx(domain)
            if not mx_pairs:
                return {**row, "_found_email": email_norm, "_verification_status": "no_mx", "_score": 0, "_checked_at": ts}

            res = await self.verifier.verify(email_norm, mx_pairs)
            status = res.get("status")
            if status == "temporary":
                retries = int(row.get("_retries", 0) or 0)
                if retries < self.args.temporary_retries:
                    delay = self.args.temporary_backoff * (2 ** retries)
                    payload = dict(row)
                    payload["_retries"] = retries + 1
                    run_at = time.time() + delay
                    async with self.retries_lock:
                        self.retries.append((run_at, payload))
                    LOG.info("Scheduled retry for %s in %.1f s (attempt %d)", email_norm, delay, retries + 1)
                    continue
                else:
                    return {**row, "_found_email": email_norm, "_verification_status": "unknown_after_retries", **res, "_checked_at": ts}
            return {**row, "_found_email": email_norm, "_verification_status": status, **res, "_checked_at": ts}
        return None

    async def run(self):
        in_path = Path(self.args.input)
        if not in_path.exists():
            LOG.error("input not found: %s", in_path)
            return 2
        out_path = Path(self.args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)

        timeout = aiohttp.ClientTimeout(total=self.http_timeout)
        headers = {"User-Agent": self.args.user_agent}
        conn = aiohttp.TCPConnector(limit_per_host=max(2, self.args.concurrency // 4), limit=0)

        async with aiohttp.ClientSession(connector=conn, timeout=timeout, headers=headers) as session:
            with open(in_path, newline="", encoding="utf-8", errors="replace") as inf, \
                 open(out_path, "w", newline="", encoding="utf-8") as outf:
                reader = csv.DictReader(inf)
                in_fields = reader.fieldnames or []
                out_fields = list(in_fields) + ["_found_email", "_verification_status", "_smtp_code", "_smtp_message", "_catch_all", "_score", "_smtp_transcript_path", "_checked_at"]
                writer = csv.DictWriter(outf, fieldnames=out_fields, extrasaction="ignore")
                writer.writeheader()

                q: asyncio.Queue = asyncio.Queue(maxsize=10000)
                stop_ev = asyncio.Event()

                # workers
                concurrency = max(2, min(self.args.concurrency, 200))
                workers = [asyncio.create_task(self._worker(q, writer, outf, session, stop_ev)) for _ in range(concurrency)]
                sched = asyncio.create_task(self.retry_scheduler(q, stop_ev))

                # signal handling
                loop = asyncio.get_event_loop()
                stop_called = False
                def _sig():
                    nonlocal stop_called
                    if not stop_called:
                        LOG.info("signal received - shutting down")
                        stop_ev.set()
                        stop_called = True
                try:
                    loop.add_signal_handler(signal.SIGINT, _sig)
                    loop.add_signal_handler(signal.SIGTERM, _sig)
                except Exception:
                    # not all event loops support add_signal_handler (e.g. Windows fallback)
                    pass

                pushed = 0
                try:
                    for row in reader:
                        if stop_ev.is_set():
                            break
                        await q.put(dict(row))
                        pushed += 1
                        if pushed % 500 == 0:
                            LOG.info("Queued rows: %d", pushed)
                    # wait until done or target reached
                    while (not q.empty() or (self.retries and not stop_ev.is_set())) and not stop_ev.is_set():
                        async with self.enriched_lock:
                            if getattr(self.args, "target", None) and self.enriched_written >= int(self.args.target):
                                LOG.info("target reached (%d)", self.enriched_written)
                                stop_ev.set()
                                break
                        await asyncio.sleep(0.5)
                finally:
                    stop_ev.set()
                    await asyncio.gather(*workers, return_exceptions=True)
                    sched.cancel()

        # cleanup
        try:
            self.verifier.mx.shutdown()
            self.verifier.prober.shutdown()
        except Exception:
            pass
        LOG.info("done: queued ~%d, enriched written: %d", pushed, self.enriched_written)
        return 0

    async def _worker(self, q: asyncio.Queue, writer: csv.DictWriter, outf, session: aiohttp.ClientSession, stop_ev: asyncio.Event):
        while not stop_ev.is_set():
            try:
                row = await asyncio.wait_for(q.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            try:
                enriched = await self.process_row(row, session)
                if enriched:
                    try:
                        writer.writerow(enriched)
                        try:
                            outf.flush(); os.fsync(outf.fileno())
                        except Exception:
                            pass
                        async with self.enriched_lock:
                            self.enriched_written += 1
                            if getattr(self.args, "target", None) and self.enriched_written >= int(self.args.target):
                                stop_ev.set()
                    except Exception:
                        LOG.exception("write failed")
            except Exception:
                LOG.exception("row processing failed")
            finally:
                try: q.task_done()
                except Exception: pass

# ---------------- CLI ----------------
def parse_args():
    p = argparse.ArgumentParser(description="Enricher: MX + SMTP + STARTTLS + retry scheduler")
    p.add_argument("--input", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--concurrency", type=int, default=30)
    p.add_argument("--smtp-timeout", type=float, default=8.0)
    p.add_argument("--mx-timeout", type=float, default=6.0)
    p.add_argument("--http-timeout", type=float, default=8.0)
    p.add_argument("--mail-from", default="verifier@example.com")
    p.add_argument("--mail-from-list", default=None)
    p.add_argument("--user-agent", default="enricher/1.0")
    p.add_argument("--disposable-file", default=None)
    p.add_argument("--skip-smtp", action="store_true")
    p.add_argument("--ports", default="25,587,465", help="comma-separated ports to try")
    p.add_argument("--per-host-limit", type=int, default=2)
    p.add_argument("--per-host-interval", type=float, default=1.0)
    p.add_argument("--global-limit", type=int, default=50)
    p.add_argument("--temporary-retries", type=int, default=2)
    p.add_argument("--temporary-backoff", type=float, default=30.0)
    p.add_argument("--target", type=int, default=10000, help="stop after this many enriched rows written")
    return p.parse_args()

def main():
    args = parse_args()
    args.ports = [int(x.strip()) for x in str(args.ports).split(",") if x.strip().isdigit()]
    logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
    LOG.info("starting enricher")
    enr = Enricher(args)
    try:
        rc = asyncio.run(enr.run())
        sys.exit(rc or 0)
    except KeyboardInterrupt:
        LOG.warning("interrupted")
        sys.exit(2)

if __name__ == "__main__":
    main()
