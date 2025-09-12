#!/usr/bin/env python3
"""
scripts/enrich.py

Async enricher: stream filtered_companies.csv, generate domain guesses,
check MX, scrape common contact pages, extract emails, write enriched_verified.csv,
stop when target verified emails reached.

Designed for GitHub Actions (6-hour-ish jobs) or local runs.
"""
import argparse
import asyncio
import csv
import re
import sys
import time
import threading
from pathlib import Path
from typing import List, Set
import dns.resolver
import aiohttp
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-']+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", re.I)
# Deterministic TLD list (order matters)
TLD_CANDIDATES = [".com", ".co.uk", ".uk", ".net", ".io", ".co", ".biz", ".org"]
CONTACT_PAGES = ["/", "/contact", "/contact-us", "/about", "/about-us", "/team", "/staff", "/people", "/privacy"]

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
    out = []
    if base:
        for t in TLD_CANDIDATES:
            out.append(base + t)
        # dotted variant (for multiword names)
        words = re.findall(r"[a-z0-9]+", company_name.lower())
        if len(words) > 1:
            out.append("".join(words) + ".com")
            out.append(".".join(words) + ".com")
    # dedupe, keep order
    seen = set()
    dedup = []
    for d in out:
        if d not in seen:
            dedup.append(d)
            seen.add(d)
    return dedup

def _mx_check_sync(domain: str, mx_timeout: float) -> bool:
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=float(mx_timeout))
        return len(answers) > 0
    except Exception:
        return False

async def mx_ok(domain: str, executor: ThreadPoolExecutor, mx_timeout: float) -> bool:
    loop = asyncio.get_event_loop()
    try:
        return await loop.run_in_executor(executor, _mx_check_sync, domain, mx_timeout)
    except Exception:
        return False

async def fetch_pages_and_extract(session: aiohttp.ClientSession, domain: str, http_timeout: float) -> Set[str]:
    found = set()
    # try https then http
    schemes = ["https://", "http://"]
    for scheme in schemes:
        base = scheme + domain
        for p in CONTACT_PAGES:
            url = base + p
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=http_timeout)) as resp:
                    if resp.status != 200:
                        continue
                    txt = await resp.text()
                    soup = BeautifulSoup(txt, "html.parser")
                    # extract mailto
                    for a in soup.select("a[href^=mailto]"):
                        href = a.get("href", "")
                        m = re.search(r"mailto:([^?]+)", href, re.I)
                        if m:
                            found.add(m.group(1).strip().lower())
                    # visible emails
                    for e in EMAIL_RE.findall(soup.get_text(" ", strip=True)):
                        found.add(e.lower())
                    if found:
                        return found
            except asyncio.CancelledError:
                raise
            except Exception:
                # ignore network/parse errors for robustness
                continue
    return found

class CSVWriter:
    def __init__(self, path: Path, fieldnames: List[str], limit: int):
        self.path = path
        self.fieldnames = fieldnames
        self.lock = threading.Lock()
        self.count = 0
        self.limit = int(limit)
        # open file sync
        self._f = open(path, "w", newline="", encoding="utf-8")
        self._writer = csv.DictWriter(self._f, fieldnames=fieldnames, extrasaction="ignore")
        self._writer.writeheader()
        self._f.flush()

    def write_row(self, row: dict):
        with self.lock:
            self._writer.writerow(row)
            self._f.flush()
            self.count += 1
            return self.count

    def reached_limit(self) -> bool:
        return self.count >= self.limit

    def close(self):
        try:
            self._f.close()
        except Exception:
            pass

async def worker(idx: int, queue: asyncio.Queue, writer: CSVWriter, args, executor: ThreadPoolExecutor, session: aiohttp.ClientSession, stop_event: asyncio.Event):
    while not stop_event.is_set():
        try:
            row = await asyncio.wait_for(queue.get(), timeout=1.0)
        except asyncio.TimeoutError:
            # if queue is empty and stop_event not set, continue waiting
            continue

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
                ok = await mx_ok(d, executor, args.mx_timeout)
                if not ok:
                    continue
                emails = await fetch_pages_and_extract(session, d, args.http_timeout)
                if emails:
                    first = sorted(emails)[0]
                    got_email = first
                    got_domain = d
                    got_source = f"https://{d} or http://{d}"
                    break

            if got_email:
                out_row = dict(row)  # preserve input columns
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
            # swallow per-row exceptions to keep pipeline robust
            pass
        finally:
            try:
                queue.task_done()
            except Exception:
                pass

async def main_async(args):
    input_path = Path(args.input)
    out_path = Path(args.output)
    if not input_path.exists():
        print(f"Input file {input_path} not found", file=sys.stderr)
        return 2

    # read header
    with open(input_path, newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        in_fieldnames = reader.fieldnames or []

    out_fieldnames = list(in_fieldnames) + ["_found_email", "_email_domain", "_website_domain", "_has_email", "_source_url", "_checked_at"]
    writer = CSVWriter(out_path, out_fieldnames, args.target)

    queue = asyncio.Queue(maxsize=10000)
    stop_event = asyncio.Event()

    executor = ThreadPoolExecutor(max_workers=200)
    timeout = aiohttp.ClientTimeout(total=args.http_timeout)
    headers = {"User-Agent": args.user_agent, "Accept": "text/html,application/xhtml+xml"}
    conn = aiohttp.TCPConnector(limit_per_host=8, limit=0)  # many hosts
    session = aiohttp.ClientSession(connector=conn, timeout=timeout, headers=headers)

    # spawn workers
    workers = [asyncio.create_task(worker(i, queue, writer, args, executor, session, stop_event)) for i in range(args.concurrency)]

    processed = 0
    # producer: stream CSV and push rows until target reached or EOF
    try:
        with open(input_path, newline="", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if stop_event.is_set():
                    break
                await queue.put(row)
                processed += 1
                # occasional yield
                if processed % 500 == 0:
                    await asyncio.sleep(0)
        # Wait until writer reached target or queue drained
        # Loop check to avoid deadlocks
        while not writer.reached_limit() and (not queue.empty()):
            await asyncio.sleep(1)
    except asyncio.CancelledError:
        pass
    finally:
        # signal workers to stop
        stop_event.set()
        # allow workers to finish current tasks
        await asyncio.gather(*workers, return_exceptions=True)
        await session.close()
        executor.shutdown(wait=False)
        writer.close()
        print(f"Processed rows (pushed): {processed}; Verified found: {writer.count}")
        return 0

def parse_args():
    p = argparse.ArgumentParser(description="Async enricher: stop at target verified emails.")
    p.add_argument("--input", required=True, help="Input CSV (filtered_companies.csv)")
    p.add_argument("--output", required=True, help="Output CSV path")
    p.add_argument("--target", type=int, default=10000, help="Target verified emails (stop when reached)")
    p.add_argument("--concurrency", type=int, default=80, help="Number of async worker tasks (HTTP concurrency)")
    p.add_argument("--http-timeout", type=float, default=8.0, help="HTTP page fetch timeout in seconds")
    p.add_argument("--mx-timeout", type=float, default=4.0, help="MX DNS check timeout in seconds")
    p.add_argument("--user-agent", default="Mozilla/5.0 (compatible; Enricher/1.0)", help="User-Agent header")
    return p.parse_args()

def main():
    args = parse_args()
    # sanity limits
    if args.concurrency < 2:
        args.concurrency = 2
    if args.concurrency > 250:
        args.concurrency = 250
    try:
        res = asyncio.run(main_async(args))
        sys.exit(res or 0)
    except Exception as e:
        print("Fatal error:", e, file=sys.stderr)
        sys.exit(2)

if __name__ == "__main__":
    main()
