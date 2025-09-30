# PowerTest — Sequential Recon Orchestrator

**Summary**  
PowerTest is a Python script that runs reconnaissance tools **sequentially**: **Nmap → DirEnum (Gobuster/Dirb) → Nikto → Sqlmap**.  
It streams output live to the console and saves timestamped reports for lab/CTF use.

---

## Features
- Strict sequential execution (Nmap first, then each tool one by one)  
- Verbose live output + saved report files  
- Timestamped report folder per run  
- Optional timeout per command  
- Auto-detects available tools (gobuster/dirb, nikto, sqlmap)  

---

## Prerequisites
- Python 3.x  
- Installed tools:
  - `nmap` (recommended with sudo for `-sS` and `-O`)  
  - `gobuster` **or** `dirb`  
  - `nikto`  
  - `sqlmap`  
- (Optional) `asciinema`, `imagemagick`, `enscript` for fancy demos/screenshots  

---

## Quick install & run
```bash
# clone the repo (example)
git clone https://github.com/<your-user>/PowerTest.git
cd PowerTest

# make script executable
chmod +x PowerTest.py

# run
./PowerTest.py
# or
python3 PowerTest.py
