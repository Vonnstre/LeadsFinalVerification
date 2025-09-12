#!/usr/bin/env python3 """ scripts/enrich.py — robust, deterministic async enricher

What it does (improvements):

deterministic domain generation

MX checks with threadpooled resolver + caching

HTTP scraping with retries, content-type guard and HTML heuristic

suppresses MarkupResemblesLocatorWarning safely

robust CSV writing with locking and fsync

graceful shutdown on signals and when target reached

extensive logging instead of silent exceptions

sane defaults and bounds for concurrency / threadpool


This file is a drop-in replacement for your previous script. It intentionally keeps the same CLI but fixes brittle behavior and runtime warnings.

Designed for reliability in CI or local runs. """

import argparse import asyncio import csv import errno import logging import os import re import signal import sys import time import threading from concurrent.futures import ThreadPoolExecutor from pathlib import Path from typing import Dict, List, Optional, Set

import aiohttp import dns.resolver from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning

------------- Configuration & constants -------------

LOG = logging.getLogger("enricher")

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-']+@[A-Za-z0-9.-]+.[A-Za-z]{2,}", re.I) TLD_CANDIDATES = [".com", ".co.uk", ".uk", ".net", ".io", ".co", ".biz", ".org"] CONTACT_PAGES = ["/", "/contact", "/contact-us", "/about", "/about-us", "/team", "/staff", "/people", "/privacy"]

If servers return odd content, inspect this many chars when deciding if it's HTML

HTML_HEURISTIC_BYTES = 512

------------- Utility functions -------------

def slug_company(name: str) -> str: if not name: return "" s = name.lower() s = re.sub(r"[^0-9a-z\s]", " ", s) s = re.sub(r"\b(ltd|limited|co|company|inc|llc|plc)\b", " ", s) s = re.sub(r"\s+", " ", s).strip() return s.replace(" ", "") if s else ""

def gen_domains(company_name: str) -> List[str]: base = slug_company(company_name) out: List[str] = [] if base: for t in TLD_CANDIDATES: out.append(base + t) words = re.findall(r"[a-z0-9]+", company_name.lower()) if len(words) > 1: out.append("".join(words) + ".com") out.append(".".join(words) + ".com") # dedupe while preserving order seen = set() dedup: List[str] = [] for d in out: if d not in seen: dedup.append(d) seen.add(d) return dedup

def _looks_like_html(txt: str) -> bool: if not txt: return False sample = txt.lstrip()[:HTML_HEURISTIC_BYTES] # must contain a tag-like char or an email symbol return bool(re.search(r"<[a-zA-Z!/]", sample) or "@" in sample)

------------- MX checking with caching -------------

class MXChecker: def init(self, mx_timeout: float, max_workers: int = 10): self.mx_timeout = float(mx_timeout) self._cache: Dict[str, bool] = {} self._lock = threading.Lock() # thread executor for blocking DNS calls self._executor = ThreadPoolExecutor(max_workers=max_workers)

def _mx_check_sync(self, domain: str) -> bool:
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=self.mx_timeout)
        return len(answers) > 0
    except Exception:
        return False

async def mx_ok(self, domain: str) -> bool:
    # fast path cache (thread-safe)
    with self._lock:
        if domain in self._cache:
            return self._cache[domain]
    loop = asyncio.get_event_loop()
    try:
        ok = await loop.run_in_executor(self._executor, self._mx_check_sync, domain)
    except Exception:
        ok = False
    with self._lock:
        self._cache[domain] = ok
    return ok

def shutdown(self):
    try:
        self._executor.shutdown(wait=False)
    except Exception:
        pass

------------- Robust CSV writer -------------

class CSVWriter: def init(self, path: Path, fieldnames: List[str], limit: int): self.path = path self.fieldnames = fieldnames self.lock = threading.Lock() self.count = 0 self.limit = int(limit) # ensure parent exists os.makedirs(path.parent, exist_ok=True) self._f = open(path, "w", newline="", encoding="utf-8") self._writer = csv.DictWriter(self._f, fieldnames=fieldnames, extrasaction="ignore") try: self._writer.writeheader() self._f.flush() try: os.fsync(self._f.fileno()) except Exception: pass except Exception as e: LOG.exception("Failed to write CSV header: %s", e) raise

def write_row(self, row: dict) -> int:
    with self.lock:
        try:
            self._writer.writerow(row)
            self._f.flush()
            try:
                os.fsync(self._f.fileno())
            except Exception:
                pass
            self.count += 1
            return self.count
        except Exception:
            LOG.exception("Failed to write CSV row")
            raise

def reached_limit(self) -> bool:
    return self.count >= self.limit

def close(self):
    try:
        self._f.close()
    except Exception:
        pass

------------- HTTP fetch with retries and robust parsing -------------

async def _fetch_text(session: aiohttp.ClientSession, url: str, timeout: float, retries: int = 2) -> Optional[str]: last_exc = None for attempt in range(retries + 1): try: async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as resp: # accept 200 and 203-like responses but skip redirects that return non-html if resp.status != 200: # log 4xx/5xx occasionally LOG.debug("Non-200 response %s for %s", resp.status, url) return None ctype = resp.headers.get("Content-Type", "") # prefer to skip obvious non-html if "html" not in ctype.lower() and "text" not in ctype.lower(): # still attempt to read small responses in case server mislabels txt = await resp.text(errors='replace') if not _looks_like_html(txt): LOG.debug("Skipping non-HTML response for %s (Content-Type=%s)", url, ctype) return None return txt txt = await resp.text(errors='replace') return txt except asyncio.CancelledError: raise except Exception as e: last_exc = e LOG.debug("Fetch attempt %d failed for %s: %s", attempt + 1, url, getattr(e, 'args', e)) # small backoff await asyncio.sleep(0.5 * (attempt + 1)) continue LOG.debug("All fetch retries failed for %s: %s", url, last_exc) return None

async def fetch_pages_and_extract(session: aiohttp.ClientSession, domain: str, http_timeout: float) -> Set[str]: found: Set[str] = set() schemes = ["https://", "http://"] for scheme in schemes: base = scheme + domain.rstrip("/") for p in CONTACT_PAGES: url = base + p try: txt = await _fetch_text(session, url, http_timeout, retries=2) if not txt: continue # quick heuristic if not _looks_like_html(txt): continue # suppress BeautifulSoup filename warnings (harmless) with warnings_suppressed(MarkupResemblesLocatorWarning): soup = BeautifulSoup(txt, "html.parser") # extract mailto anchors for a in soup.select("a[href^=mailto]"): href = a.get("href", "") m = re.search(r"mailto:([^?]+)", href, re.I) if m: found.add(m.group(1).strip().lower()) # visible emails text = soup.get_text(" ", strip=True) for e in EMAIL_RE.findall(text): found.add(e.lower()) if found: return found except asyncio.CancelledError: raise except Exception: LOG.debug("Error parsing %s", url, exc_info=True) continue return found

small context manager to suppress warnings

from contextlib import contextmanager import warnings

@contextmanager def warnings_suppressed(category): with warnings.catch_warnings(): warnings.filterwarnings("ignore", category=category) yield

------------- Worker and main pipeline -------------

async def worker(idx: int, queue: asyncio.Queue, writer: CSVWriter, args, mxchecker: MXChecker, session: aiohttp.ClientSession, stop_event: asyncio.Event): LOG.info("Worker %d started", idx) try: while not stop_event.is_set(): try: row = await asyncio.wait_for(queue.get(), timeout=1.0) except asyncio.TimeoutError: # check stop condition continue

try:
            company = (row.get("CompanyName") or row.get("company") or "").strip()
            candidate_domains = gen_domains(company)
            got_email = None
            got_domain = None
            got_source = ""
            for d in candidate_domains:
                if stop_event.is_set():
                    break
                if not d:
                    continue
                try:
                    ok = await mxchecker.mx_ok(d)
                except Exception:
                    ok = False
                if not ok:
                    continue
                try:
                    emails = await fetch_pages_and_extract(session, d, args.http_timeout)
                except Exception:
                    emails = set()
                if emails:
                    first = sorted(emails)[0]
                    got_email = first
                    got_domain = d
                    got_source = f"https://{d}"
                    break

            if got_email:
                out_row = dict(row)
                out_row.update({
                    "_found_email": got_email,
                    "_email_domain": got_email.split("@")[-1],
                    "_website_domain": got_domain,
                    "_has_email": True,
                    "_source_url": got_source,
                    "_checked_at": int(time.time())
                })
                count = writer.write_row(out_row)
                if count >= writer.limit:
                    stop_event.set()
            # mark task done
        except Exception:
            LOG.exception("Unhandled error processing row: %s", row)
        finally:
            try:
                queue.task_done()
            except Exception:
                pass
finally:
    LOG.info("Worker %d stopped", idx)

async def main_async(args): input_path = Path(args.input) out_path = Path(args.output) if not input_path.exists(): LOG.error("Input file %s not found", input_path) return 2

# read header
try:
    with open(input_path, newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        in_fieldnames = reader.fieldnames or []
except Exception:
    LOG.exception("Failed to read input CSV header")
    return 2

out_fieldnames = list(in_fieldnames) + ["_found_email", "_email_domain", "_website_domain", "_has_email", "_source_url", "_checked_at"]

writer = CSVWriter(out_path, out_fieldnames, args.target)

# bounds
concurrency = max(2, min(args.concurrency, 250))
mx_workers = max(2, min(200, concurrency * 2))

queue = asyncio.Queue(maxsize=10000)
stop_event = asyncio.Event()

mxchecker = MXChecker(args.mx_timeout, max_workers=mx_workers)

timeout = aiohttp.ClientTimeout(total=args.http_timeout)
headers = {"User-Agent": args.user_agent, "Accept": "text/html,application/xhtml+xml"}
conn = aiohttp.TCPConnector(limit_per_host=max(4, concurrency // 4), limit=0, ssl=False)

# create session inside context to ensure proper cleanup
async with aiohttp.ClientSession(connector=conn, timeout=timeout, headers=headers) as session:
    # spawn workers
    workers = [asyncio.create_task(worker(i, queue, writer, args, mxchecker, session, stop_event)) for i in range(concurrency)]

    processed = 0

    # graceful cancellation on SIGINT/SIGTERM
    loop = asyncio.get_event_loop()
    stop_called = False

    def _signal_handler():
        nonlocal stop_called
        if not stop_called:
            LOG.info("Received termination signal, stopping gracefully...")
            stop_event.set()
            stop_called = True

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _signal_handler)
        except NotImplementedError:
            # Windows asyncio doesn't implement add_signal_handler for the event loop used in some environments
            pass

    # producer
    try:
        with open(input_path, newline="", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if stop_event.is_set():
                    break
                # ensure row is a dict with string keys
                await queue.put(row)
                processed += 1
                if processed % 500 == 0:
                    LOG.info("Queued rows: %d", processed)
                    await asyncio.sleep(0)
    except asyncio.CancelledError:
        pass
    except Exception:
        LOG.exception("Producer encountered an error")
    finally:
        # wait for results or stop
        try:
            while not writer.reached_limit() and (not queue.empty()) and (not stop_event.is_set()):
                await asyncio.sleep(0.5)
            # if writer didn't reach limit but queue empty, wait a bit for workers
            await asyncio.sleep(0.5)
        except asyncio.CancelledError:
            pass

    # stop workers
    stop_event.set()
    await asyncio.gather(*workers, return_exceptions=True)

# cleanup
try:
    mxchecker.shutdown()
except Exception:
    pass
writer.close()
LOG.info("Processed rows (pushed): %d; Verified found: %d", processed, writer.count)
return 0

------------- CLI -------------

def parse_args(): p = argparse.ArgumentParser(description="Async enricher: stop at target verified emails.") p.add_argument("--input", required=True, help="Input CSV (filtered_companies.csv)") p.add_argument("--output", required=True, help="Output CSV path") p.add_argument("--target", type=int, default=10000, help="Target verified emails (stop when reached)") p.add_argument("--concurrency", type=int, default=20, help="Number of async worker tasks (HTTP concurrency)") p.add_argument("--http-timeout", type=float, default=10.0, help="HTTP page fetch timeout in seconds") p.add_argument("--mx-timeout", type=float, default=6.0, help="MX DNS check timeout in seconds") p.add_argument("--user-agent", default="Mozilla/5.0 (compatible; Enricher/1.0)", help="User-Agent header") return p.parse_args()

def main(): args = parse_args() # configure logging logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s") try: res = asyncio.run(main_async(args)) sys.exit(res or 0) except Exception as e: LOG.exception("Fatal error") sys.exit(2)

if name == "main": main()

