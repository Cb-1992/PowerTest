#!/usr/bin/env python3
"""
PowerTest.py - Script interactif (verbeux) pour lancer Nmap, Gobuster/Dirb, Nikto, sqlmap
EXÉCUTION STRICTEMENT SÉQUENTIELLE : Nmap -> Gobuster/Dirb -> Nikto -> Sqlmap
"""

import os
import sys
import shutil
import subprocess
from datetime import datetime
from urllib.parse import urlparse

# ====== Configuration par défaut ======
DEFAULT_WORDLIST = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
DEFAULT_EXTS = "php,html,txt,asp,aspx"
GOBUSTER_THREADS = "50"
SQLMAP_THREADS = "5"
# ======================================

def check_tool(name):
    return shutil.which(name) is not None

def timestamp():
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def safe_mkdir(path):
    os.makedirs(path, exist_ok=True)

def normalize_target(raw, scheme_hint="http"):
    if raw.startswith("http://") or raw.startswith("https://"):
        p = urlparse(raw)
        return p.hostname, raw.rstrip("/")
    if "?" in raw or "=" in raw:
        if not raw.startswith("http"):
            raw = scheme_hint + "://" + raw
        p = urlparse(raw)
        return p.hostname, raw.rstrip("/")
    host = raw.strip()
    url = f"{scheme_hint}://{host}"
    return host, url

def stream_run_and_save(cmd_list, out_path, timeout=None):
    """Stream stdout/stderr to console and write to a file. Return exit code."""
    with open(out_path, "ab") as fout:
        header = f"\n\n== Command: {' '.join(cmd_list)} ==\nStarted: {datetime.now().isoformat()}\n"
        fout.write(header.encode())
    try:
        proc = subprocess.Popen(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    except Exception as e:
        msg = f"[!] ERROR launching command: {e}\n"
        with open(out_path, "ab") as fout:
            fout.write(msg.encode())
        print(msg)
        return -2

    try:
        while True:
            chunk = proc.stdout.readline()
            if not chunk:
                if proc.poll() is not None:
                    break
                continue
            # print and save
            try:
                print(chunk.decode(errors="replace"), end="")
            except:
                print(chunk, end="")
            with open(out_path, "ab") as fout:
                fout.write(chunk)
        rc = proc.wait(timeout=timeout)
        with open(out_path, "ab") as fout:
            fout.write(f"\nReturn code: {rc}\nFinished: {datetime.now().isoformat()}\n".encode())
        return rc
    except subprocess.TimeoutExpired:
        proc.kill()
        with open(out_path, "ab") as fout:
            fout.write(b"\n[!] TIMEOUT - command killed by script\n")
        print("\n[!] TIMEOUT - command killed by script")
        return -1
    except Exception as e:
        with open(out_path, "ab") as fout:
            fout.write(f"\n[!] EXEC ERROR: {e}\n".encode())
        print(f"\n[!] EXEC ERROR: {e}")
        return -2

def write_header(outpath, title):
    with open(outpath, "wb") as fh:
        fh.write(f"{title}\nCreated: {datetime.now().isoformat()}\n\n".encode())

def main():
    print("\nPowerTest (sequential) — verbose streaming\n")
    target_raw = input("Target (IP/hostname/URL): ").strip()
    if not target_raw:
        print("No target provided. Exiting.")
        sys.exit(1)
    scheme = input("Scheme if URL needed (http/https) [http]: ").strip() or "http"
    wordlist = input(f"Wordlist [{DEFAULT_WORDLIST}]: ").strip() or DEFAULT_WORDLIST
    exts = input(f"Extensions (csv) [{DEFAULT_EXTS}]: ").strip() or DEFAULT_EXTS
    timeout_sec = input("Timeout per command in seconds (0 = none) [0]: ").strip()
    try:
        timeout_sec = int(timeout_sec or 0)
        if timeout_sec <= 0:
            timeout_sec = None
    except:
        timeout_sec = None

    host, target_url = normalize_target(target_raw, scheme_hint=scheme)
    ts = timestamp()
    outdir = f"PowerTest_reports_{host}_{ts}"
    safe_mkdir(outdir)
    print(f"\nReports -> {outdir}\nNormalized: host={host} url={target_url}\n")

    # Tools check
    required = ["nmap"]
    optional = ["gobuster","dirb","nikto","sqlmap"]
    tools = {t: check_tool(t) for t in required+optional}
    for k,v in tools.items():
        print(f"  - {k}: {'OK' if v else 'MISSING'}")
    if not tools["nmap"]:
        print("nmap is required. Install and retry.")
        sys.exit(2)
    if not (tools.get("gobuster") or tools.get("dirb")):
        print("Either gobuster or dirb required. Install one and retry.")
        sys.exit(3)
    if not tools.get("nikto"):
        print("nikto not found. Please install.")
        sys.exit(4)
    if not tools.get("sqlmap"):
        print("sqlmap not found. Please install.")
        sys.exit(5)

    # Prepare commands (strict order)
    reports = []

    # 1) Nmap - forced first
    nmap_out = os.path.join(outdir, f"nmap_{host}_{ts}.txt")
    write_header(nmap_out, f"Nmap scan report for {host}")
    nmap_cmd = [
        "sudo","nmap",
        "-sS","-p-","-T4","--open","-v","-sV","-O",
        "--script","default,vuln","--reason","--max-retries","3","--host-timeout","1m",
        host
    ]
    reports.append(("Nmap", nmap_cmd, nmap_out))

    # 2) Dirbuster/Gobuster
    dir_out = os.path.join(outdir, f"dir_{host}_{ts}.txt")
    exts_list = exts.replace(" ", "")
    if tools.get("gobuster"):
        gcmd = ["gobuster","dir","-u",target_url,"-w",wordlist,"-x",exts_list,"-t",GOBUSTER_THREADS,"-k"]
    else:
        exts_for_dirb = ",".join(["."+e for e in exts_list.split(",")])
        gcmd = ["dirb", target_url, wordlist, "-X", exts_for_dirb]
    write_header(dir_out, f"Dir enum report for {target_url}")
    reports.append(("DirEnum", gcmd, dir_out))

    # 3) Nikto
    nikto_out = os.path.join(outdir, f"nikto_{host}_{ts}.txt")
    nkcmd = ["nikto","-h", target_url, "-output", nikto_out]
    # nikto writes directly to file, but keep streaming for stdout as well
    write_header(nikto_out, f"Nikto report for {target_url}")
    reports.append(("Nikto", nkcmd, nikto_out))

    # 4) Sqlmap
    sql_out = os.path.join(outdir, f"sqlmap_{host}_{ts}.txt")
    if ("?" in target_raw) or ("=" in target_raw):
        url_to_test = target_raw if target_raw.startswith("http") else target_url
        smcmd = ["sqlmap","--batch","--random-agent","-u",url_to_test,"--threads",SQLMAP_THREADS,"--level","3","--risk","2"]
    else:
        smcmd = ["sqlmap","--batch","--random-agent","-u",target_url,"--crawl","1","--threads",SQLMAP_THREADS,"--level","2","--risk","1"]
    write_header(sql_out, f"Sqlmap report for {target_url}")
    reports.append(("Sqlmap", smcmd, sql_out))

    # Execute strictly sequentially
    for name, cmd, outpath in reports:
        print("\n" + "="*40)
        print(f"Starting step: {name}")
        print("Command ->", " ".join(cmd))
        rc = stream_run_and_save(cmd, outpath, timeout=timeout_sec)
        print(f"Step {name} finished with return code {rc}. Output saved to: {outpath}")

        # Safety pause optional: let user abort if needed
        if name != reports[-1][0]:
            resp = input("Continue to next step? (Enter to continue, 'q' then Enter to stop) [Enter]: ").strip().lower()
            if resp == "q":
                print("Execution stopped by user.")
                break

    # Summary
    print("\nAll done (or stopped). Report files in:", outdir)
    for f in sorted(os.listdir(outdir)):
        print(" -", os.path.join(outdir, f))
    print("\nNote: run only against authorized/test targets. Some scans are intrusive.")
    sys.exit(0)

if __name__ == "__main__":
    main()
