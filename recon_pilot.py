#!/usr/bin/env python3
"""
recon-pilot: your eJPT-style recon co-pilot.

1. Fast asyncio TCP connect scan (no root needed)
2. Banner grabbing + service/version fingerprinting
3. Flags well-known vulnerable versions (offline knowledge base)
4. Builds a prioritised "next steps" enumeration checklist per service
5. Writes pentest notes (Markdown) + JSON so nothing gets lost during an exam or engagement

Only scan systems you own or have written permission to test.
Author: Martin Ivanov (Martun1) | License: MIT
"""
from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import re
import socket
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path

__version__ = "1.0.0"
ROOT = Path(__file__).resolve().parent


class C:
    R, G, Y, B, M, CY, BD, DM, X = ("\033[91m", "\033[92m", "\033[93m", "\033[94m", "\033[95m",
                                    "\033[96m", "\033[1m", "\033[2m", "\033[0m")

    @classmethod
    def off(cls):
        for k in ("R", "G", "Y", "B", "M", "CY", "BD", "DM", "X"):
            setattr(cls, k, "")


TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 465, 587, 993, 995, 1433, 1521,
             2049, 2121, 2222, 3000, 3306, 3389, 5000, 5432, 5900, 5985, 6379, 8000, 8008, 8080, 8443, 8888,
             9000, 9200, 10000, 11211, 27017]

KB = json.loads((ROOT / "knowledge_base.json").read_text(encoding="utf-8"))


@dataclass
class Service:
    port: int
    state: str = "open"
    name: str = "unknown"
    banner: str = ""
    product: str = ""
    version: str = ""
    alerts: list[dict] = field(default_factory=list)
    next_steps: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
#  Scanning
# --------------------------------------------------------------------------- #
PROBES = {  # what to send if the service doesn't talk first
    "http": b"HEAD / HTTP/1.0\r\nHost: target\r\nUser-Agent: recon-pilot\r\n\r\n",
    "redis": b"INFO server\r\n",
}
HTTP_PORTS = {80, 443, 3000, 5000, 8000, 8008, 8080, 8443, 8888, 9000, 9200, 10000}


async def probe(host: str, port: int, timeout: float) -> Service | None:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except (OSError, asyncio.TimeoutError):
        return None
    svc = Service(port)
    data = b""
    try:
        try:
            data = await asyncio.wait_for(reader.read(1024), 1.2)  # server-first protocols (FTP, SSH, SMTP...)
        except asyncio.TimeoutError:
            pass
        if not data:
            payload = PROBES["redis"] if port == 6379 else PROBES["http"]
            writer.write(payload)
            await writer.drain()
            try:
                data = await asyncio.wait_for(reader.read(2048), 1.5)
            except asyncio.TimeoutError:
                pass
    except OSError:
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
    svc.banner = data.decode("utf-8", errors="replace").strip()
    if port == 6379 and svc.banner.startswith("$"):
        svc.banner = svc.banner.split("\n", 1)[-1].strip()  # drop RESP length header
    fingerprint(svc)
    return svc


async def scan(host: str, ports: list[int], concurrency: int, timeout: float, progress: bool) -> list[Service]:
    sem = asyncio.Semaphore(concurrency)
    done = 0
    found: list[Service] = []

    async def worker(p):
        nonlocal done
        async with sem:
            s = await probe(host, p, timeout)
        done += 1
        if s:
            found.append(s)
        if (progress and done % 50 == 0) or done == len(ports):
            pct = done * 100 // len(ports)
            print(f"\r  {C.DM}scanning{C.X} [{'█' * (pct // 4)}{'░' * (25 - pct // 4)}] {pct:3d}%  "
                  f"{C.G}{len(found)} open{C.X}", end="", flush=True)

    await asyncio.gather(*(worker(p) for p in ports))
    print()
    return sorted(found, key=lambda s: s.port)


# --------------------------------------------------------------------------- #
#  Fingerprinting & knowledge base
# --------------------------------------------------------------------------- #
SIGNATURES = [
    ("ftp", r"^220[- ].*?(vsFTPd|ProFTPD|Pure-FTPd|FileZilla Server|Microsoft FTP Service)[ /]*([\d.a-z]*)"),
    ("smtp", r"^220[- ].*?(Postfix|Exim|Sendmail|Microsoft ESMTP)[ /]*([\d.]*)"),
    ("smtp", r"^220[- ].*SMTP"),
    ("ftp", r"^220[- ]"),
    ("ssh", r"^SSH-[\d.]+-(OpenSSH|dropbear)_?([\w.]*)"),
    ("ssh", r"^SSH-"),
    ("mysql", r"(\d+\.\d+\.\d+)[-\w.]*\x00.*(mysql_native_password|caching_sha2)"),
    ("http", r"^HTTP/\d\.\d.*?Server: ([\w\-]+)/?([\d.]*)"),
    ("http", r"^HTTP/"),
    ("redis", r"redis_version:([\d.]+)"),
    ("pop3", r"^\+OK"),
    ("imap", r"^\* OK"),
    ("vnc", r"^RFB \d+\.\d+"),
]
PORT_NAMES = {21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3", 111: "rpcbind",
              135: "msrpc", 139: "netbios-ssn", 143: "imap", 389: "ldap", 443: "https", 445: "smb", 1433: "mssql",
              1521: "oracle", 2049: "nfs", 3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc",
              5985: "winrm", 6379: "redis", 9200: "elasticsearch", 11211: "memcached", 27017: "mongodb"}


def fingerprint(svc: Service) -> None:
    b = svc.banner
    for name, rx in SIGNATURES:
        m = re.search(rx, b, re.S | re.I | re.M)
        if m:
            svc.name = name
            g = [x for x in m.groups() if x] if m.groups() else []
            if name == "mysql" and g:
                svc.product, svc.version = "MySQL", g[0]
            elif name == "redis" and g:
                svc.product, svc.version = "Redis", g[0]
            elif g:
                svc.product = g[0]
                svc.version = g[1] if len(g) > 1 else ""
            break
    else:
        svc.name = PORT_NAMES.get(svc.port, "unknown")
    if svc.name == "http" and (svc.port in (443, 8443)):
        svc.name = "https"
    # knowledge base: vulnerable versions
    full = f"{svc.product} {svc.version}".strip().lower()
    for entry in KB["vulnerable_versions"]:
        if re.search(entry["match"], full + " " + b.lower(), re.I):
            svc.alerts.append(entry)
    # misconfig hints from banner content
    for entry in KB["banner_hints"]:
        if re.search(entry["match"], b, re.I) and (entry.get("service") in (None, svc.name)):
            svc.alerts.append(entry)
    svc.next_steps = [s for s in KB["next_steps"].get(svc.name, KB["next_steps"]["unknown"])]


# --------------------------------------------------------------------------- #
#  Output
# --------------------------------------------------------------------------- #
SEV_C = {"CRITICAL": "M", "HIGH": "R", "MEDIUM": "Y", "INFO": "B", "LOW": "B"}


def printable_line(banner: str) -> str:
    """First human-readable line of a banner (binary protocols like MySQL are cleaned up)."""
    for line in banner.splitlines():
        if line.startswith("#"):
            continue
        clean = "".join(ch if 32 <= ord(ch) < 127 else " " for ch in line)
        clean = re.sub(r"\s{2,}", " ", clean).strip()
        if len(re.sub(r"[^\w.]", "", clean)) >= 3:
            return clean
    return ""


def print_results(target: str, services: list[Service], elapsed: float, nports: int, show_steps: bool) -> None:
    print(f"\n  {C.BD}PORT     SERVICE      VERSION                      BANNER{C.X}")
    print(f"  {C.DM}{'─' * 92}{C.X}")
    for s in services:
        ver = f"{s.product} {s.version}".strip() or "-"
        ban = printable_line(s.banner)[:38]
        flag = f" {C.R}⚠{C.X}" if s.alerts else ""
        print(f"  {C.G}{str(s.port) + '/tcp':<8}{C.X} {C.CY}{s.name:<12}{C.X} {ver[:28]:<28} {C.DM}{ban}{C.X}{flag}")
    alerts = [(s, a) for s in services for a in s.alerts]
    if alerts:
        print(f"\n  {C.BD}⚠  Findings{C.X}")
        for s, a in sorted(alerts, key=lambda x: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(x[1]["severity"])):
            sc = getattr(C, SEV_C[a["severity"]])
            ref = f" {C.DM}({a['ref']}){C.X}" if a.get("ref") else ""
            print(f"  {sc}{a['severity']:<8}{C.X} {s.port:<5} {a['title']}{ref}")
    if show_steps and services:
        print(f"\n  {C.BD}➜  Next steps{C.X} {C.DM}(copy & paste){C.X}")
        for s in services:
            print(f"  {C.CY}[{s.port}/{s.name}]{C.X}")
            for step in s.next_steps[:3]:
                print(f"    {C.DM}${C.X} {step.replace('{T}', target).replace('{P}', str(s.port))}")
    print(f"\n  {C.BD}Done:{C.X} {len(services)} open / {nports} scanned in {elapsed:.2f}s"
          f"  ·  {len(alerts)} finding(s)\n")


def write_notes(path: Path, target: str, services: list[Service], elapsed: float) -> None:
    L = [f"# Recon notes: {target}", "",
         f"> Generated by recon-pilot v{__version__} on {datetime.now():%Y-%m-%d %H:%M}. Scan time {elapsed:.1f}s.", "",
         "## Open ports", "", "| Port | Service | Version | Banner |", "|---|---|---|---|"]
    for s in services:
        ban = printable_line(s.banner)[:60].replace("|", "\\|")
        L.append(f"| {s.port}/tcp | {s.name} | {(s.product + ' ' + s.version).strip() or '-'} | `{ban}` |")
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    alerts = sorted([(s, a) for s in services for a in s.alerts], key=lambda x: order.index(x[1]["severity"]))
    L += ["", "## Findings", ""]
    L += [f"- [ ] **{a['severity']}** port {s.port}: {a['title']}" + (f" ({a['ref']})" if a.get("ref") else "")
          + (f"\n  - {a['detail']}" if a.get("detail") else "") for s, a in alerts] or ["_None flagged automatically. Keep enumerating!_"]
    L += ["", "## Enumeration checklist", ""]
    for s in services:
        L.append(f"### {s.port}/{s.name}")
        L += [f"- [ ] `{st.replace('{T}', target).replace('{P}', str(s.port))}`" for st in s.next_steps]
        L.append("")
    L += ["## Credentials found", "", "| Service | User | Password/Hash | Source |", "|---|---|---|---|", "| | | | |", "",
          "## Notes", "", "- "]
    path.write_text("\n".join(L) + "\n", encoding="utf-8")


def parse_ports(spec: str) -> list[int]:
    if spec == "top":
        return TOP_PORTS
    if spec == "all":
        return list(range(1, 65536))
    out = set()
    for part in spec.split(","):
        if "-" in part:
            a, b = part.split("-")
            out.update(range(int(a), int(b) + 1))
        else:
            out.add(int(part))
    if not out or min(out) < 1 or max(out) > 65535:
        raise ValueError("ports must be in 1-65535")
    return sorted(out)


def resolve(target: str) -> str:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        raise SystemExit(f"[!] cannot resolve {target}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="recon-pilot", description="Async port scanner + service intel + eJPT-style notes")
    ap.add_argument("target", help="IP or hostname")
    ap.add_argument("-p", "--ports", default="top", help="'top' (default), 'all', '1-1024', '22,80,443'")
    ap.add_argument("-c", "--concurrency", type=int, default=500)
    ap.add_argument("-t", "--timeout", type=float, default=1.0, help="connect timeout in seconds")
    ap.add_argument("-o", "--notes", type=Path, help="write Markdown pentest notes")
    ap.add_argument("--json", type=Path, help="write JSON results")
    ap.add_argument("--no-steps", action="store_true", help="hide the next-steps checklist")
    ap.add_argument("--authorized", action="store_true",
                    help="confirm you have permission (required for public IPs)")
    ap.add_argument("--no-color", action="store_true")
    a = ap.parse_args(argv)
    if a.no_color:
        C.off()

    ip = resolve(a.target)
    addr = ipaddress.ip_address(ip)
    if not (addr.is_private or addr.is_loopback) and not a.authorized:
        print(f"{C.Y}[!]{C.X} {ip} is a public address. Only scan systems you are authorized to test.\n"
              f"    Re-run with --authorized to confirm (e.g. scanme.nmap.org is explicitly allowed).")
        return 3
    ports = parse_ports(a.ports)
    print(f"\n  {C.BD}{C.CY}✈ recon-pilot v{__version__}{C.X}  target {C.BD}{a.target}{C.X} ({ip})  "
          f"{C.DM}{len(ports)} ports · concurrency {a.concurrency}{C.X}")
    t0 = time.perf_counter()
    services = asyncio.run(scan(ip, ports, a.concurrency, a.timeout, progress=sys.stdout.isatty()))
    elapsed = time.perf_counter() - t0
    print_results(a.target, services, elapsed, len(ports), not a.no_steps)
    if a.notes:
        write_notes(a.notes, a.target, services, elapsed)
        print(f"  {C.G}[+]{C.X} notes → {a.notes}")
    if a.json:
        a.json.write_text(json.dumps({"target": a.target, "ip": ip, "scanned": len(ports), "elapsed": elapsed,
                                      "services": [asdict(s) for s in services]}, indent=2))
        print(f"  {C.G}[+]{C.X} json  → {a.json}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] interrupted")
        sys.exit(130)
