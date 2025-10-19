#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Hunter Recon Runner (wildcard-filtered) — complete, corrected version
Features:
- amass passive auto-run when installed
- optional --amass-active for active amass (background)
- per-tool subdomains saved to subdomains/<tool>.txt and printed with headings
- final.txt built from subdomains/*.txt (unique) and scanned with httpx -> final_alive.txt
- bruteforce uses puredns/dnsx if present, otherwise embedded dig loop (resolver configurable)
- fallback capture for tools that print to stdout (run_tool captures stdout->out file if no file created)
- --pretty enables ANSI colored, bold headings
- anubis & knockpy removed
"""
from __future__ import annotations
import argparse
import os
import shlex
import shutil
import subprocess
import json
import uuid
import random
import sys
from datetime import datetime, timezone
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---- Config / constants ----
DEVNULL = subprocess.DEVNULL
TOOL_TIMEOUT_SHORT = 900
TOOL_TIMEOUT_LONG = 1500
TOOL_TIMEOUT_DIR = 3600
DEFAULT_DNS_WORDLIST = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt"
DEFAULT_ALT_WORDLIST = "alternative_wordlist.txt"
DEFAULT_RESOLVER = os.environ.get("RESOLVER", "1.1.1.1")

# ---- Helpers ----
def now_month_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m")

def ensure_dir(p: Path) -> Path:
    p.mkdir(parents=True, exist_ok=True)
    return p

def which(b: str) -> str | None:
    return shutil.which(b)

def safe_read_lines(p: Path) -> list[str]:
    p = Path(p)
    if not p.exists():
        return []
    try:
        return [l.rstrip("\n") for l in p.read_text(encoding="utf-8", errors="ignore").splitlines() if l.strip()]
    except Exception:
        return []

def write_text(p: Path, txt: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(txt, encoding="utf-8")

def shlex_quote(s: str) -> str:
    import shlex as _sh
    return _sh.quote(str(s))

# ---- ANSI Colors ----
class C:
    H = "\033[1m"
    G = "\033[32m"
    Y = "\033[33m"
    R = "\033[31m"
    B = "\033[34m"
    X = "\033[0m"

def colorize(enabled: bool, code: str, txt: str) -> str:
    return f"{code}{txt}{C.X}" if enabled else txt

# ---- Hunter class ----
class Hunter:
    def __init__(self, domain: str, outdir: str = ".", wordlist: str | None = None,
                 bruteforce: bool = False, amass_active: bool = False, rate: int | None = None,
                 alt_wordlist_path: str | None = None, resolver: str | None = None, pretty: bool = False):
        self.domain = domain.strip().lower()
        self.first = self.domain.split()[0]
        self.month = now_month_str()
        self.out = Path(outdir).resolve() / f"{self.first}_{self.month}"
        self.raw = self.out / "raw_outputs"
        self.subdir = self.out / "subdomains"
        ensure_dir(self.raw)
        ensure_dir(self.subdir)

        self.wordlist = wordlist or DEFAULT_DNS_WORDLIST
        self.bruteforce = bruteforce
        self.amass_active = amass_active
        self.rate = rate or 200
        self.alt_wordlist_path = alt_wordlist_path or DEFAULT_ALT_WORDLIST
        self.resolver = resolver or DEFAULT_RESOLVER
        self.pretty = pretty

        self.all: set[str] = set()
        self.zero_result_tools: set[str] = set()

        self.validated_file = self.out / "validated.txt"
        self.validated_filtered_file = self.out / "validated_filtered.txt"
        self.final_file = self.out / "final.txt"
        self.alive_file = self.out / "final_alive.txt"
        self.wildcard_info_file = self.out / "wildcard_info.txt"

        self.wildcard_ips: set[str] = set()
        self.wildcard_cnames: set[str] = set()
        self.wildcard_ready = False

        # Nice header
        print(colorize(self.pretty, C.H + C.B, f"[*] Target: {self.domain}  |  Output: {self.out.name}"))
        print(colorize(self.pretty, C.Y, f"[*] DNS wordlist: {self.wordlist}"))

    # ---- Pretty headings & save/print per-tool ----
    def _pretty_heading(self, title: str, kind: str = "info") -> None:
        if self.pretty:
            sep = "=" * 60
            print("\n" + sep)
            if kind == "info":
                print(colorize(True, C.H + C.B, title))
            elif kind == "warn":
                print(colorize(True, C.H + C.Y, title))
            elif kind == "ok":
                print(colorize(True, C.H + C.G, title))
            elif kind == "err":
                print(colorize(True, C.H + C.R, title))
            print("-" * 60)
        else:
            print(f"\n-- {title} --")

    def _save_and_print_tool_results(self, tool_name: str, hosts: set[str]) -> None:
        hosts_sorted = sorted(hosts)
        outp = self.subdir / f"{tool_name}.txt"
        write_text(outp, "\n".join(hosts_sorted))
        self._pretty_heading(tool_name.capitalize(), kind="info")
        if hosts_sorted:
            for h in hosts_sorted:
                print(h)
        else:
            print(colorize(self.pretty, C.Y, "(no results)"))
        self.all.update(hosts_sorted)

    # ---- DNS helpers ----
    def _dnsx_records(self, hosts: list[str]) -> dict[str, set[str]]:
        recs: dict[str, set[str]] = {}
        if not hosts:
            return recs
        if not which("dnsx"):
            for h in hosts:
                s = set()
                try:
                    if which("host"):
                        r = subprocess.run(["host", "-t", "A", h], capture_output=True, text=True, timeout=6)
                        for ln in r.stdout.splitlines():
                            if " has address " in ln:
                                s.add(ln.strip().split()[-1])
                except Exception:
                    pass
                if not s:
                    try:
                        r = subprocess.run(["dig", "+short", h, "@" + self.resolver], capture_output=True, text=True, timeout=6)
                        for ln in r.stdout.splitlines():
                            if ln.strip():
                                s.add(ln.strip())
                    except Exception:
                        pass
                if s:
                    recs[h] = s
            return recs

        tmp = self.raw / "__dnsx_batch.txt"
        write_text(tmp, "\n".join(hosts))
        out = self.raw / "__dnsx_batch_out.txt"
        cmd = f"cat {tmp} | dnsx -silent -a -cname -resp -rcode noerror -o {out}"
        try:
            subprocess.run(cmd, shell=True, stdout=DEVNULL, stderr=DEVNULL, timeout=TOOL_TIMEOUT_SHORT)
        except Exception:
            pass

        for ln in safe_read_lines(out):
            parts = ln.split()
            if not parts:
                continue
            host = parts[0].rstrip(".").lower()
            if host not in recs:
                recs[host] = set()
            for tok in parts[1:]:
                t = tok.strip().rstrip(".")
                if t and t not in ("[A]", "[CNAME]", "[NS]", "[AAAA]", "[TXT]", "[MX]"):
                    recs[host].add(t.lower())
        try:
            tmp.unlink()
            out.unlink()
        except Exception:
            pass
        return recs

    def detect_wildcard(self, probes: int = 3) -> None:
        if self.wildcard_ready:
            return
        labels = []
        for _ in range(probes):
            rnd = uuid.uuid4().hex[:8] + str(random.randint(100, 999))
            labels.append(f"{rnd}.{self.domain}")
        print(colorize(self.pretty, C.Y, f"[*] Wildcard detection: probing {len(labels)} random labels..."))
        recs = self._dnsx_records(labels)
        ipset, cnset = set(), set()
        for vals in recs.values():
            for v in vals:
                if v.replace(".", "").isdigit():
                    ipset.add(v)
                else:
                    cnset.add(v)
        self.wildcard_ips = ipset
        self.wildcard_cnames = cnset
        self.wildcard_ready = True
        wc_lines = []
        wc_lines.append(f"# Wildcard detected = {bool(ipset or cnset)}")
        if ipset:
            wc_lines.append("A_IPS: " + ", ".join(sorted(ipset)))
        if cnset:
            wc_lines.append("CNAMEs: " + ", ".join(sorted(cnset)))
        if not (ipset or cnset):
            wc_lines.append("none")
        write_text(self.wildcard_info_file, "\n".join(wc_lines))
        print(colorize(self.pretty, C.G, "[✓] Wildcard signature saved."))

    def filter_wildcard_hosts(self, hosts: set[str]) -> set[str]:
        if not hosts:
            return set()
        self.detect_wildcard()
        if not (self.wildcard_ips or self.wildcard_cnames):
            return set(hosts)
        recs = self._dnsx_records(sorted(hosts))
        kept = set()
        for h, vals in recs.items():
            ips = {v for v in vals if v.replace(".", "").isdigit()}
            cnames = {v for v in vals if not v.replace(".", "").isdigit()}
            only_wc = True
            if ips and not ips.issubset(self.wildcard_ips):
                only_wc = False
            if cnames and not cnames.issubset(self.wildcard_cnames):
                only_wc = False
            if not only_wc:
                kept.add(h)
        removed = set(hosts) - kept
        print(colorize(self.pretty, C.G, f"[✓] Wildcard filter: kept {len(kept)}, removed {len(removed)} (wildcard-like)"))
        return kept

    # ---- Tool runner with fallback capture ----
    def run_tool(self, name: str, cmd: str, out: Path) -> set[str]:
        out = Path(out)
        out.parent.mkdir(parents=True, exist_ok=True)
        found: set[str] = set()
        timeout = TOOL_TIMEOUT_SHORT if "amass" not in name else TOOL_TIMEOUT_LONG

        # 1) try running normally (tools that write files themselves)
        try:
            subprocess.run(cmd, shell=True, stdout=DEVNULL, stderr=DEVNULL, timeout=timeout)
        except subprocess.TimeoutExpired:
            print(colorize(self.pretty, C.R, f"[{name}] Timed out."))
        except Exception as e:
            print(colorize(self.pretty, C.R, f"[{name}] Error: {e}"))

        # 2) if expected out file not created, capture stdout/stderr and write to out
        if not out.exists():
            try:
                p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
                if p.stdout:
                    out.write_text(p.stdout, encoding="utf-8")
                if p.stderr:
                    (out.parent / f"{out.name}.stderr").write_text(p.stderr, encoding="utf-8")
            except subprocess.TimeoutExpired:
                print(colorize(self.pretty, C.R, f"[{name}] Timed out during capture fallback."))
            except Exception as e:
                print(colorize(self.pretty, C.R, f"[{name}] Fallback error: {e}"))

        # 3) if still no out -> mark zero and print empty
        if not out.exists():
            self.zero_result_tools.add(name)
            self._save_and_print_tool_results(name, set())
            return set()

        lines = safe_read_lines(out)
        for l in lines:
            ll = l.strip().lower()
            if self.domain in ll:
                h = ll.split()[0].split(",")[0].split("/")[0].rstrip(".")
                if h and not h.startswith("*") and not h.startswith("."):
                    found.add(h)
        if len(found) == 0:
            self.zero_result_tools.add(name)
        self._save_and_print_tool_results(name, found)
        return found

    # ---- Specific tool runners ----
    def run_amass_passive(self) -> set[str]:
        if not which("amass"):
            self._save_and_print_tool_results("amass_passive", set())
            return set()
        outp = self.raw / "amass_passive.txt"
        cmd = f"amass enum -passive -d {shlex_quote(self.domain)} -nocolor -o {outp}"
        return self.run_tool("amass_passive", cmd, outp)

    def run_amass_active(self) -> set[str]:
        if not which("amass"):
            self._save_and_print_tool_results("amass_active", set())
            return set()
        outp = self.raw / "amass_active.txt"
        cmd = f"amass enum -active -d {shlex_quote(self.domain)} -nocolor -o {outp}"
        return self.run_tool("amass_active", cmd, outp)

    def dns_bruteforce(self) -> set[str]:
        results: set[str] = set()
        wl = Path(self.wordlist)
        if not wl.exists():
            print(colorize(self.pretty, C.R, f"[-] DNS wordlist missing: {wl}"))
            self.zero_result_tools.add("bruteforce")
            self._save_and_print_tool_results("bruteforce", set())
            return results

        print(colorize(self.pretty, C.Y, f"[*] Starting DNS bruteforce (wordlist: {wl.name}, resolver: {self.resolver})"))
        puredns_out = self.raw / "bruteforce_puredns.txt"
        dnsx_out = self.raw / "bruteforce_dnsx.txt"

        if which("puredns"):
            cmd = f"puredns bruteforce {shlex_quote(str(wl))} {shlex_quote(self.domain)} -r /etc/resolv.conf -t 50 > {puredns_out}"
            try:
                subprocess.run(cmd, shell=True, stdout=DEVNULL, stderr=DEVNULL, timeout=TOOL_TIMEOUT_LONG)
            except Exception:
                pass
            for ln in safe_read_lines(puredns_out):
                h = ln.strip().lower().rstrip(".")
                if h and self.domain in h:
                    results.add(h)
            self._save_and_print_tool_results("bruteforce_puredns", results)

        if which("dnsx"):
            tmp = self.raw / "__dns_bf_candidates.txt"
            with tmp.open("w", encoding="utf-8") as t, open(wl, "r", encoding="utf-8", errors="ignore") as w:
                for ln in w:
                    s = ln.strip()
                    if s:
                        t.write(f"{s}.{self.domain}\n")
            cmd = f"cat {tmp} | dnsx -silent -a -resp -o {dnsx_out}"
            try:
                subprocess.run(cmd, shell=True, stdout=DEVNULL, stderr=DEVNULL, timeout=TOOL_TIMEOUT_LONG)
            except Exception:
                pass
            for ln in safe_read_lines(dnsx_out):
                parts = ln.split()
                if parts:
                    h = parts[0].strip().rstrip(".")
                    if h and self.domain in h:
                        results.add(h)
            try:
                tmp.unlink()
            except Exception:
                pass
            self._save_and_print_tool_results("bruteforce_dnsx", results)

        # fallback dig loop if neither puredns nor dnsx present or results empty
        if not (which("puredns") or which("dnsx")) or not results:
            fallback = self.dig_resolve_wordlist(str(wl))
            results.update(fallback)
            self._save_and_print_tool_results("bruteforce_dig_fallback", fallback)

        if not results:
            self.zero_result_tools.add("bruteforce")
            self._save_and_print_tool_results("bruteforce", set())

        write_text(self.raw / "bruteforce_combined.txt", "\n".join(sorted(results)))
        return results

    def dig_resolve_wordlist(self, wl_path: str) -> set[str]:
        resolved: set[str] = set()
        p = Path(wl_path)
        if not p.exists():
            return resolved
        try:
            with p.open("r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    s = line.strip()
                    if not s or s.startswith("#"):
                        continue
                    host = f"{s}.{self.domain}".lower()
                    try:
                        r = subprocess.run(["dig", "+short", host, "@" + self.resolver],
                                           capture_output=True, text=True, timeout=4)
                        ips = r.stdout.strip().splitlines()
                        if ips:
                            resolved.add(host.rstrip("."))
                    except Exception:
                        pass
        except Exception:
            pass
        return resolved

    def enumerate(self) -> None:
        tools = {
            "assetfinder": f"assetfinder --subs-only {shlex_quote(self.domain)} > {self.raw/'assetfinder.txt'}",
            "sublist3r": f"sublist3r -d {shlex_quote(self.domain)} -o {self.raw/'sublist3r.txt'}",
            "subfinder": f"subfinder -d {shlex_quote(self.domain)} -silent -o {self.raw/'subfinder.txt'}",
            "chaos": f"chaos -d {shlex_quote(self.domain)} -silent -o {self.raw/'chaos.txt'}",
            "findomain": f"findomain -t {shlex_quote(self.domain)} -q -u {self.raw/'findomain.txt'}",
        }

        if which("amass"):
            tools["amass_passive"] = f"amass enum -passive -d {shlex_quote(self.domain)} -nocolor -o {self.raw/'amass_passive.txt'}"

        future_to_tool = {}
        bg_futures = {}

        with ThreadPoolExecutor(max_workers=6) as bg:
            if self.bruteforce:
                bg_futures[bg.submit(self.dns_bruteforce)] = "bruteforce_bg"

            if self.amass_active and which("amass"):
                bg_futures[bg.submit(self.run_amass_active)] = "amass_active_bg"

            with ThreadPoolExecutor(max_workers=min(len(tools) + 2, 10)) as ex:
                for name, cmd in tools.items():
                    exe = name.split()[0]
                    if name == "amass_passive":
                        if which("amass"):
                            future_to_tool[ex.submit(self.run_tool, name, cmd, self.raw / f"{name}.txt")] = name
                        else:
                            self._save_and_print_tool_results(name, set())
                    else:
                        if which(exe):
                            future_to_tool[ex.submit(self.run_tool, name, cmd, self.raw / f"{name}.txt")] = name
                        else:
                            self._save_and_print_tool_results(name, set())

                for fut in as_completed(list(future_to_tool.keys())):
                    name = future_to_tool.get(fut)
                    if not name:
                        continue
                    try:
                        res = fut.result()
                        if res:
                            self.all.update(res)
                    except Exception as e:
                        print(colorize(self.pretty, C.R, f"[{name}] exception: {e}"))

            if bg_futures:
                for fut in as_completed(list(bg_futures.keys())):
                    try:
                        res = fut.result()
                        if isinstance(res, set) and res:
                            self.all.update(res)
                    except Exception as e:
                        print(colorize(self.pretty, C.R, f"[bg] exception: {e}"))

        # retry amass_passive once if zero-result
        if "amass_passive" in self.zero_result_tools and which("amass"):
            try:
                retry_out = self.raw / "amass_passive_retry.txt"
                retry_cmd = f"amass enum -passive -d {shlex_quote(self.domain)} -nocolor -o {retry_out}"
                subprocess.run(retry_cmd, shell=True, stdout=DEVNULL, stderr=DEVNULL, timeout=300)
                _ = self.run_tool("amass_passive_retry", retry_cmd, retry_out)
            except Exception:
                pass

        write_text(self.out / "raw_merged.txt", "\n".join(sorted(self.all)))
        print(colorize(self.pretty, C.G, f"[*] Enumeration complete: {len(self.all)} unique candidates"))

    # vhost brute + ffuf/gobuster dir brute (kept concise)
    def dns_from_overlay_prefixes(self) -> set[str]:
        wl = Path(self.alt_wordlist_path)
        if not wl.exists():
            print(colorize(self.pretty, C.Y, f"[-] Overlay DNS skipped (no list: {wl})"))
            self._save_and_print_tool_results("overlay_resolved", set())
            return set()
        print(colorize(self.pretty, C.Y, f"[*] Overlay prefixes -> DNS candidates using {wl.name}"))
        cands = set()
        for line in safe_read_lines(wl):
            p = line.strip().lower()
            if not p or p.startswith("#"):
                continue
            h = f"{p}.{self.domain}".rstrip(".")
            if all(ch.isalnum() or ch in "-." for ch in h):
                cands.add(h)
        if not cands:
            self._save_and_print_tool_results("overlay_resolved", set())
            return set()
        recs = self._dnsx_records(sorted(cands))
        resolved = set(recs.keys())
        if resolved:
            self._save_and_print_tool_results("overlay_resolved", resolved)
            write_text(self.out / "overlay_resolved.txt", "\n".join(sorted(resolved)))
            print(colorize(self.pretty, C.G, f"[✓] Overlay DNS resolved {len(resolved)} hosts"))
        else:
            print(colorize(self.pretty, C.Y, "[!] Overlay DNS: no resolved hosts."))
            self._save_and_print_tool_results("overlay_resolved", set())
        self.all.update(resolved)
        return resolved

    def vhost_bruteforce(self, base_hosts: set | None = None) -> set[str]:
        wl = Path(self.alt_wordlist_path)
        if not wl.exists():
            print(colorize(self.pretty, C.Y, f"[-] VHOST list missing: {wl}"))
            self._save_and_print_tool_results("vhost", set())
            return set()
        if not base_hosts:
            base_hosts = set()
            if self.validated_filtered_file.exists():
                base_hosts.update(safe_read_lines(self.validated_filtered_file))
            elif self.validated_file.exists():
                base_hosts.update(safe_read_lines(self.validated_file))
            else:
                base_hosts.add(self.domain)
        print(colorize(self.pretty, C.Y, f"[*] VHOST brute on {len(base_hosts)} base host(s) with {wl.name}"))
        found: set[str] = set()

        # gobuster vhost
        if which("gobuster"):
            for base in sorted(base_hosts):
                op = self.raw / f"vhost_gobuster_{base.replace('.', '_')}.txt"
                for proto in ("https", "http"):
                    cmd = ["gobuster", "vhost", "-u", f"{proto}://{base}", "-w", str(wl), "-t", "100", "-o", str(op), "-q"]
                    try:
                        subprocess.run(cmd, stdout=DEVNULL, stderr=DEVNULL, timeout=TOOL_TIMEOUT_LONG)
                        for ln in safe_read_lines(op):
                            cand = ln.split()[0].strip().lower().rstrip(".")
                            if cand and (cand.endswith("." + self.domain) or cand == self.domain):
                                found.add(cand)
                    except subprocess.TimeoutExpired:
                        pass

        # ffuf host header via IPs
        ips: set[str] = set()

        def _resolve_ips(h: str) -> set[str]:
            loc = set()
            if which("dnsx"):
                tmp = self.raw / f"__resolve_{h}.txt"
                try:
                    subprocess.run(f"echo {h} | dnsx -silent -a -o {tmp}", shell=True, stdout=DEVNULL, stderr=DEVNULL, timeout=30)
                    for ln in safe_read_lines(tmp):
                        p = ln.split()
                        if len(p) >= 2:
                            loc.add(p[1].strip())
                except Exception:
                    pass
                try:
                    tmp.unlink()
                except Exception:
                    pass
            if not loc and which("host"):
                try:
                    r = subprocess.run(["host", "-t", "A", h], capture_output=True, text=True, timeout=10)
                    for ln in r.stdout.splitlines():
                        if " has address " in ln:
                            loc.add(ln.strip().split()[-1])
                except Exception:
                    pass
            return loc

        for bh in sorted(base_hosts):
            ips.update(_resolve_ips(bh))

        if which("ffuf") and ips:
            for ip in sorted(ips):
                outj = self.raw / f"vhost_ffuf_{ip.replace('.', '_')}.json"
                cmd = ["ffuf", "-u", f"http://{ip}/", "-H", f"Host: FUZZ.{self.domain}",
                       "-w", str(wl), "-of", "json", "-o", str(outj),
                       "-mc", "200,301,302,401,403", "-t", "100", "-timeout", "10"]
                try:
                    subprocess.run(cmd, stdout=DEVNULL, stderr=DEVNULL, timeout=TOOL_TIMEOUT_LONG)
                    if outj.exists():
                        try:
                            data = json.loads(outj.read_text(encoding="utf-8"))
                            for res in data.get("results", []):
                                fu = None
                                if isinstance(res.get("input"), dict):
                                    fu = res["input"].get("FUZZ")
                                if fu:
                                    found.add(f"{fu}.{self.domain}".lower().rstrip("."))
                        except Exception:
                            pass
                except subprocess.TimeoutExpired:
                    pass

        if found:
            recs = self._dnsx_records(sorted(found))
            resolved = set(recs.keys())
            if resolved:
                filtered = self.filter_wildcard_hosts(resolved)
            else:
                filtered = set()
            write_text(self.out / "vhost_candidates.txt", "\n".join(sorted(filtered if filtered else resolved)))
            self._save_and_print_tool_results("vhost", filtered if filtered else resolved)
            print(colorize(self.pretty, C.G, f"[✓] VHOST brute candidates: {len(filtered if filtered else resolved)}"))
        else:
            self._save_and_print_tool_results("vhost", set())
            print(colorize(self.pretty, C.Y, "[!] VHOST brute: 0 candidates."))
        return found

    def run_gobuster_ffuf(self, hosts: set[str]) -> None:
        if not self.alt_wordlist_path or not Path(self.alt_wordlist_path).exists():
            print(colorize(self.pretty, C.Y, f"[-] Dir brute skipped (no list: {self.alt_wordlist_path})"))
            self._save_and_print_tool_results("dir_bruteforce", set())
            return
        wl = Path(self.alt_wordlist_path)

        if which("ffuf"):
            print(colorize(self.pretty, C.Y, f"[*] FFUF Directory Bruteforce ({len(hosts)} hosts) with {wl.name}"))
            for h in hosts:
                for proto in ("http", "https"):
                    op = self.raw / f"ffuf_{h}_{proto}.json"
                    cmd = (f"ffuf -u {proto}://{h}/FUZZ -w {shlex_quote(str(wl))} "
                           f"-recursion -recursion-depth 1 -mc 200,301,302,403,401 "
                           f"-e .html,.php,.txt,.bak -of json -o {op}")
                    try:
                        subprocess.run(cmd, shell=True, stdout=DEVNULL, stderr=DEVNULL, timeout=TOOL_TIMEOUT_DIR)
                    except subprocess.TimeoutExpired:
                        pass
            print(colorize(self.pretty, C.G, "[*] FFUF dir brute complete."))
            self._save_and_print_tool_results("dir_bruteforce", set())
        elif which("gobuster"):
            print(colorize(self.pretty, C.Y, f"[*] GoBuster Directory Bruteforce ({len(hosts)} hosts) with {wl.name}"))
            out_all = self.out / "dir_bruteforce_results.txt"
            with open(out_all, "a", encoding="utf-8") as out:
                for i, h in enumerate(hosts):
                    cmd = ["gobuster", "dir", "-u", f"http://{h}", "-w", str(wl), "-q", "-t", "50", "-o",
                           str(self.raw / f"gobuster_{h}.txt"), "-r"]
                    try:
                        r = subprocess.run(cmd, capture_output=True, text=True, timeout=max(20, TOOL_TIMEOUT_DIR // max(1, len(hosts))))
                        if r.stdout:
                            out.write(f"\n--- Results for http://{h} ---\n{r.stdout}")
                    except subprocess.TimeoutExpired:
                        pass
            print(colorize(self.pretty, C.G, "[*] GoBuster dir brute complete."))
            self._save_and_print_tool_results("dir_bruteforce", set())
        else:
            print(colorize(self.pretty, C.Y, "[-] Dir brute skipped: ffuf/gobuster not found."))
            self._save_and_print_tool_results("dir_bruteforce", set())

    # ---- Validation & httpx ----
    def validate(self) -> set[str]:
        if not self.all:
            print(colorize(self.pretty, C.Y, "[!] No candidates to validate."))
            self._save_and_print_tool_results("validated", set())
            return set()
        tmp = self.raw / "temp_candidates.txt"
        write_text(tmp, "\n".join(sorted(self.all)))
        validated: set[str] = set()
        if which("dnsx"):
            cmd = f"cat {tmp} | dnsx -silent -a -cname -resp -o {self.validated_file}"
            try:
                subprocess.run(cmd, shell=True, stdout=DEVNULL, stderr=DEVNULL, timeout=TOOL_TIMEOUT_SHORT)
            except Exception:
                pass
            for s in safe_read_lines(self.validated_file):
                h = s.split()[0].rstrip(".")
                if h and self.domain in h:
                    validated.add(h)
            self._save_and_print_tool_results("validated", validated)
        else:
            for h in sorted(self.all):
                try:
                    if which("host"):
                        r = subprocess.run(["host", "-t", "A", h], capture_output=True, text=True, timeout=5)
                        if "has address" in r.stdout or "is an alias for" in r.stdout:
                            validated.add(h)
                except Exception:
                    pass
            write_text(self.validated_file, "\n".join(sorted(validated)))
            self._save_and_print_tool_results("validated", validated)

        print(colorize(self.pretty, C.G, f"[*] dns validated total: {len(validated)}"))
        filtered = self.filter_wildcard_hosts(validated) if validated else set()
        write_text(self.validated_filtered_file, "\n".join(sorted(filtered)))
        self._save_and_print_tool_results("validated_filtered", filtered)
        print(colorize(self.pretty, C.G, f"[✓] validated_filtered: {len(filtered)}"))
        return filtered

    def probe_httpx_and_write(self, candidates: set[str]) -> set[str]:
        if not candidates:
            print(colorize(self.pretty, C.Y, "[-] No candidates to probe with httpx."))
            self._save_and_print_tool_results("httpx_alive", set())
            return set()
        if not which("httpx"):
            print(colorize(self.pretty, C.R, "[-] httpx not found."))
            self._save_and_print_tool_results("httpx_alive", set())
            return set()
        temp = self.out / "httpx_input.txt"
        write_text(temp, "\n".join(sorted(candidates)))
        out_json = self.out / "httpx_out.json"
        cmd = f"cat {temp} | httpx -silent -status-code -title -follow-redirects -json -o {out_json}"
        try:
            subprocess.run(cmd, shell=True, stdout=DEVNULL, stderr=DEVNULL, timeout=TOOL_TIMEOUT_LONG)
        except Exception:
            pass
        alive: set[str] = set()
        for line in safe_read_lines(out_json):
            try:
                j = json.loads(line)
                url = j.get("url") or j.get("input") or j.get("host")
                if not url:
                    continue
                host = url.split("://")[-1].split("/")[0].split(":")[0]
                if self.domain in host:
                    alive.add(host.lower())
            except Exception:
                pass
        write_text(self.alive_file, "\n".join(sorted(alive)))
        self._save_and_print_tool_results("httpx_alive", alive)
        try:
            temp.unlink()
        except Exception:
            pass
        return alive

    def build_final_from_subdir(self) -> set[str]:
        merged: set[str] = set()
        if self.subdir.exists():
            for f in self.subdir.glob("*.txt"):
                merged.update(safe_read_lines(f))
        merged.update(self.all)
        finals = sorted(merged)
        write_text(self.final_file, "\n".join(finals))
        print(colorize(self.pretty, C.G, f"[*] final.txt built: {len(finals)} entries"))
        return set(finals)

    def finalize_and_show(self) -> None:
        # final from self.all (but final.txt already built possibly)
        finals = sorted(set(self.all))
        write_text(self.final_file, "\n".join(finals))
        print("\n" + "=" * 60)
        print(colorize(self.pretty, C.H + C.B, f"[FINAL CANDIDATES] ({len(finals)})"))
        print("-" * 60)
        for h in finals:
            print(h)
        print("=" * 60)
        alive = set(safe_read_lines(self.alive_file)) if Path(self.alive_file).exists() else set()
        print(colorize(self.pretty, C.H + C.G, f"[FINAL ALIVE] ({len(alive)})"))
        for h in sorted(alive):
            print(h)
        print("=" * 60)

# ---- CLI ----
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Hunter Recon Runner (wildcard-filtered) — corrected full script")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("-d", "--domain", help="Single domain")
    g.add_argument("-f", "--file", help="File with domains")
    p.add_argument("--auto", action="store_true", help="Full flow")
    p.add_argument("--bruteforce", action="store_true", help="Enable DNS bruteforce")
    p.add_argument("--amass-active", action="store_true", help="Enable amass active")
    p.add_argument("-w", "--wordlist", default=None, help=f"DNS wordlist (default: {DEFAULT_DNS_WORDLIST})")
    p.add_argument("-aw", "--alt-wordlist", dest="alt_wordlist", default=None, help=f"Alt wordlist for vhost/dir/overlay (default: {DEFAULT_ALT_WORDLIST})")
    p.add_argument("-o", "--output", default=".", help="Output dir")
    p.add_argument("--rate", type=int, default=None, help="DNS rate")
    p.add_argument("--resolver", default=None, help=f"Resolver IP for dig fallback (default: {DEFAULT_RESOLVER})")
    p.add_argument("--pretty", action="store_true", help="Pretty-print headers and sections (ANSI colors)")
    return p.parse_args()

def main() -> None:
    args = parse_args()
    dns_wl = args.wordlist or DEFAULT_DNS_WORDLIST
    alt_wl = args.alt_wordlist or DEFAULT_ALT_WORDLIST
    targets = [args.domain] if args.domain else safe_read_lines(Path(args.file))
    if len(targets) == 1 and args.bruteforce and not args.rate:
        print("============================================================")
        print("Recon advice based on target count:")
        print("  targets: 1  |  suggested puredns rate: 200 qps")
        print("============================================================")
    core = ["subfinder", "assetfinder", "amass", "dnsx", "httpx", "chaos", "findomain", "puredns", "ffuf", "gobuster"]
    missing = [t for t in core if not which(t)]
    if missing:
        print(colorize(args.pretty, C.Y, f"[-] WARNING: missing tools: {', '.join(missing)}"))
    else:
        print(colorize(args.pretty, C.G, "[+] All core tools appear present."))

    for domain in targets:
        h = Hunter(domain=domain, outdir=args.output, wordlist=dns_wl,
                   bruteforce=args.bruteforce, amass_active=args.amass_active,
                   rate=args.rate, alt_wordlist_path=alt_wl, resolver=args.resolver, pretty=args.pretty)
        if args.auto:
            # 1) enumeration (includes amass_passive if available)
            h.enumerate()
            # 2) overlay prefixes -> DNS
            h.dns_from_overlay_prefixes()
            # 3) validate + wildcard filter (reporting)
            h.validate()
            # 4) probe existing validated for vhost base if needed
            validated_filtered = set(safe_read_lines(h.validated_filtered_file)) if Path(h.validated_filtered_file).exists() else set()
            alive_guess = set(safe_read_lines(h.alive_file)) if Path(h.alive_file).exists() else validated_filtered
            # 5) vhost brute
            h.vhost_bruteforce(base_hosts=alive_guess if alive_guess else validated_filtered)
            # 6) dir brute (if have alive/validated)
            targets_for_dir = alive_guess if alive_guess else validated_filtered
            if targets_for_dir:
                h.run_gobuster_ffuf(targets_for_dir)
            else:
                print(colorize(args.pretty, C.Y, "[-] Dir brute skipped: no alive/validated hosts."))

            # 7) build final from subdomains/* (unique)
            finals = h.build_final_from_subdir()

            # 8) probe httpx over final.txt
            h.probe_httpx_and_write(finals)

            # 9) finalize & show
            h.finalize_and_show()
        elif args.bruteforce:
            h.dns_bruteforce()
        else:
            print("No action specified. Use --auto or --bruteforce.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
    except Exception as e:
        print(f"[!] Fatal error: {e}")
