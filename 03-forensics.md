# Forensics Cheatsheet

**This is a standalone forensics event** — no live boxes to hack, no Linux/Windows privesc. You are **handed artifacts** (a memory dump, a disk image, a pcap, event logs, a suspicious document) and a **question list**, and scored on exact answers. This tab is built to get you from "here are the files" to "here is the answer" fast.

Read it in this order on game day:
1. **Section 0** — install everything tonight so nothing blocks you tomorrow.
2. **Section 1** — triage any artifact in the first 5 minutes.
3. **Section 4** — the full per-incident-type walkthroughs (the meat).
4. **Section 6** — answer-format discipline so correct answers aren't marked wrong.

---

## Contents

- [How to read & run these commands](#reading--running-these-commands)
- [0. Toolkit Setup](#0-toolkit-setup-do-this-the-night-before)
  - [0. Python — pip is locked down on the Pwnbox](#0-python--pip-is-usually-locked-down-on-the-pwnbox)
  - [0a. One-shot apt base](#0a-one-shot-apt-base)
  - [0b. Memory forensics — Volatility 3 + 2](#0b-memory-forensics--volatility-3-primary--volatility-2-legacy-fallback)
  - [0c. Timeline — Plaso](#0c-timeline--plaso-log2timeline)
  - [0d. Windows event logs (.evtx)](#0d-windows-event-logs-evtx)
  - [0e. Windows registry + artifact parsers](#0e-windows-registry--artifact-parsers)
  - [0f. Documents, mail, browsers](#0f-documents-mail-browsers)
  - [0g. Stego / carving extras](#0g-stego--carving-extras)
  - [0h. Runtimes & Windows-only-tool fallbacks](#0h-runtimes--windows-only-tool-fallbacks-youre-on-a-linux-pwnbox)
  - [0i. Wordlists + final sanity check](#0i-wordlists--final-sanity-check)
- [▶ Game-Day Runbook — literal step-by-step (START HERE)](#game-day-runbook--literal-step-by-step-start-here)
- [1. Triage — the first 5 minutes](#1-triage--the-first-5-minutes-on-any-artifact)
- [2. Standalone File & Stego Analysis](#2-standalone-file--stego-analysis)
- [3. Artifact Analysis — tool map by type](#3-artifact-analysis--tool-map-by-type)
- [4. Full Incident Walkthroughs](#4-full-incident-walkthroughs)
  - [4.0 Master flow — any artifact](#40-master-flow--run-this-for-any-artifact-every-time)
  - [4.1 Containers, forensic images & VM files](#41-containers-forensic-images--vm-files--get-to-a-mountable-form-first)
  - [4a. Windows memory dump](#4a-windows-memory-dump-memraw--vmem--dmp)
  - [4b. Windows disk image](#4b-windows-disk-image-e01--vmdk--img)
  - [4c. Network capture (pcap)](#4c-network-capture-pcap--pcapng)
  - [4d. Windows event logs (evtx)](#4d-windows-event-logs-evtx)
  - [4e. Linux server compromise](#4e-linux-server-compromise-disk-image--triage-tarball)
  - [4f. Malicious document / phishing](#4f-malicious-document--phishing-docx-doc-xlsm-pdf-eml)
  - [4g. Browser artifacts](#4g-browser-artifacts-history--downloads--cache)
  - [4h. Mobile backup (Android / iOS)](#4h-mobile-backup-android--ios)
  - [4i. Correlate across artifacts](#4i-correlate-across-artifacts-when-you-get-more-than-one)
- [5. Volatility Deep-Dive](#5-volatility-deep-dive-memory-analysis-reference)
- [6. Answer-Format Discipline](#6-answer-format-discipline--common-question-patterns)
- [7. Fast Timeline Building & Correlation](#7-fast-timeline-building--correlation)
- [8. Unstuck — when any phase stalls](#8-unstuck--when-any-phase-stalls)
- [9. Checking which CVE produced the evidence](#9-checking-which-cve-produced-the-evidence)

---

## Reading & Running These Commands

Every command here has **placeholders you swap for your own values.** The rule: if a token is in `<angle brackets>`, in ALL-CAPS, or starts with `$`, **change it** — everything else is literal, type it as-is. And always read the `#` comment after a command; it says what the command does and usually which part to change.

**What to swap in:**

| You'll see… | Put in its place | Where that value comes from |
| --- | --- | --- |
| `mem.raw`, `evidence/mem.raw`, `capture.pcap`, `disk.img`, `<f>`, `<artifact>` | your artifact's real filename / path | the file they gave you |
| `$OFF` or `<offset>` (disk commands) | the partition's **sector offset** | the `Start` column of `mmls <image>` |
| `<pid>` | a process ID | from `vol … windows.pslist` / `pstree` |
| `--virtaddr <addr>` | a file's virtual offset | from `vol … windows.filescan` output |
| `<keyword>` | what you're hunting for | e.g. `flag`, `.ps1`, a username |
| `TARGET_IP`, `<your-ip>`, `IOC`, `10.10.14.7` | the relevant IP | the brief, or something you found |
| `/mnt/disk`, `/mnt/vm`, `out/`, `~/case/chal1` | a folder you create | run `mkdir -p <it>` first |
| `2026-11-24..2026-11-26`, dates in filters | the incident's date window | the question's timeframe |
| `/usr/share/wordlists/rockyou.txt` | your wordlist path | already there after setup 0i |

**Where do I run each tool from?** Almost everything here is installed system-wide, so it's a **global command — run it from any folder** (best: your case folder, `cd ~/case/chal1`). You do **not** need to `cd` into a tool's directory for these. The few exceptions:

| Tool | How you actually run it | `cd` into its folder? |
| --- | --- | --- |
| `vol` (Volatility 3, pipx install) | `vol -f <img> <plugin>` — from anywhere | no |
| Volatility 3 (if you git-cloned it instead) | `python3 ~/tools/vol3/vol.py -f <img> <plugin>` | no — just give the full path to `vol.py` |
| **Chainsaw / Hayabusa** | `cd ~/tools/chainsaw && ./chainsaw hunt …` | **yes** — they read their bundled rules from that folder (or pass full paths to the rules) |
| RegRipper | `perl ~/tools/regripper/rip.pl -r <hive> -p <plugin>` | no |
| analyzeMFT / ALEAPP / iLEAPP / prefetch.py (from source) | `python3 <path>/<script>.py …` | no — full path to the script |
| EZ tools via dotnet | `dotnet ~/tools/ez/MFTECmd.dll …` | no |

**The exceptions as full, runnable commands** (copy, then swap the filenames for yours):
```bash
# Volatility 3 (pipx install) — global; run it from your case folder
vol -f evidence/mem.raw windows.pstree

# Volatility 3 (if you git-cloned it instead) — identical, just the full path to vol.py
python3 ~/tools/vol3/vol.py -f evidence/mem.raw windows.pstree

# Chainsaw — you cd IN, so point at evidence + output with FULL paths
cd ~/tools/chainsaw
./chainsaw hunt ~/case/chal1/evidence/evtx/ -s sigma/ --mapping mappings/sigma-event-logs-all.yml -r rules/ --csv ~/case/chal1/out/

# Hayabusa — same idea: cd in, use full paths
cd ~/tools/hayabusa
./hayabusa csv-timeline -d ~/case/chal1/evidence/evtx/ -o ~/case/chal1/out/timeline.csv

# RegRipper — run from anywhere; -r is the hive file, -p is the plugin
perl ~/tools/regripper/rip.pl -r evidence/SYSTEM -p shimcache > out/shimcache.txt

# A from-source Python tool (ALEAPP / iLEAPP / analyzeMFT) — full path to the .py
python3 ~/tools/aleapp/aleapp.py -t fs -i evidence/extraction/ -o out/android

# EZ tool via dotnet — full path to the .dll
dotnet ~/tools/ez/MFTECmd.dll -f 'evidence/$MFT' --csv out/
```
> After you `cd` into Chainsaw/Hayabusa's folder you've **left your case folder**, so give the artifact and the output as full paths (`~/case/chal1/…`), not `evidence/…` — otherwise the tool looks for them inside its own directory.

> **The evidence does NOT need to sit in the tool's folder.** Volatility, tshark, oletools, etc. all take the file as a *path* argument (`vol -f evidence/mem.raw …`, `tshark -r evidence/cap.pcap …`), so keep every artifact in your one `~/case/chal1/evidence/` folder and point tools at it from there. The *only* time you need full paths is the Chainsaw/Hayabusa `cd` case just above.

**One more:** any command that writes into `out/` (e.g. `--export-objects http,out/`) needs that folder to exist first — `mkdir -p out`. The runbook's Step 1 already creates `evidence/`, `out/` and `notes/` for you.

---

## 0. Toolkit Setup (do this the night before)

**The org's Pwnbox is Linux (Parrot/Ubuntu/Kali-style).** Every tool below is Linux-native or cross-platform; the handful that are classically Windows (the EZ tools, DeepBlueCLI) have Linux-native replacements mapped in **0h**. Each install line has a fallback: `apt` → `pipx`/`pip --break-system-packages` → `git clone` + run the script directly. If egress is blocked tomorrow, everything here must already be installed — **don't leave installs for game day.** The quickest safety net: run the one-shot block (0a), then 0b–0g, then verify with the loop in 0i.

### 0. Python — pip is usually locked down on the Pwnbox

`pip install` often fails (externally-managed-environment, or no direct PyPI), but **`python3` always works.** Use this ladder top-to-bottom until one sticks — and remember the last rung needs no install at all:

```bash
# 1. apt-packaged version first (no pip involved)
sudo apt install -y python3-<tool>          # e.g. python3-oletools, python3-impacket

# 2. pipx — installs each tool in its own env; get pipx from APT, not pip
sudo apt install -y pipx && pipx ensurepath
pipx install <tool>

# 3. pip, forced past the "externally-managed" block
python3 -m pip install <tool> --break-system-packages
#    (pip module itself missing?  python3 -m ensurepip --upgrade  )

# 4. isolated venv (never touches system python)
python3 -m venv ~/venv && source ~/venv/bin/activate && python3 -m pip install <tool>

# 5. run STRAIGHT FROM SOURCE — no install at all (most robust, always works)
git clone https://github.com/<user>/<repo> ~/tools/<repo>
python3 ~/tools/<repo>/<script>.py --help
```

> **Rule for the rest of this tab:** wherever you see `pipx install X` or `pip install X`, if it fails drop to rung 3 (`--break-system-packages`), then rung 5 (clone + `python3 script.py`). Volatility 3, oletools, analyzeMFT, regipy, hindsight, windowsprefetch all run fine straight from a git clone with `python3` — no packaging needed.

### 0a. One-shot apt base

```bash
sudo apt update && sudo apt install -y \
  python3-pip python3-venv pipx git curl wget unzip p7zip-full \
  sleuthkit autopsy ewf-tools libewf-dev \
  wireshark tshark tcpdump \
  binwalk foremost bulk-extractor scalpel testdisk \
  john \
  libimage-exiftool-perl ssdeep \
  steghide outguess pngcheck \
  pdfid pdf-parser qpdf poppler-utils \
  default-jre ruby ruby-dev
pipx ensurepath
```

> If `apt install wireshark` asks "allow non-superusers to capture": answer **Yes** (you'll read saved pcaps either way).

### 0b. Memory forensics — Volatility 3 (primary) + Volatility 2 (legacy fallback)

```bash
# Volatility 3 — main tool
pipx install volatility3          # gives the `vol` command
vol --help | head                  # sanity check
# fallbacks if pip/pipx are locked down (see the Python ladder above):
#   python3 -m pip install volatility3 --break-system-packages
#   git clone https://github.com/volatilityfoundation/volatility3 ~/tools/vol3
#   python3 ~/tools/vol3/vol.py -f mem.raw windows.info      # runs straight from source
# NOTE: every `vol ...` command in this tab also works as `python3 ~/tools/vol3/vol.py ...`

# Symbol tables auto-download on first use; pre-warm internet-dependent fetch now.
# For Linux memory dumps you may need a custom ISF symbol table (see 4a / 5).

# Volatility 2 — only for old dumps vol3 can't parse (Python 2)
git clone https://github.com/volatilityfoundation/volatility ~/tools/vol2
# run with: python2 ~/tools/vol2/vol.py -f mem.raw --profile=<Profile> <plugin>
```

Run vol3 as `vol -f mem.raw windows.info` (or `python3 -m volatility3 ...`). Keep a scratch dir: `mkdir -p ~/case/out`.

### 0c. Timeline — Plaso (log2timeline)

```bash
sudo apt install -y plaso-tools 2>/dev/null || pipx install plaso
log2timeline.py --version
# Heavy deps? Use the official Docker image instead:
#   docker pull log2timeline/plaso
#   docker run -v $PWD:/data log2timeline/plaso log2timeline.py /data/out.plaso /data/evidence
```

### 0d. Windows event logs (.evtx)

```bash
# evtx_dump — evtx -> XML/JSON (Rust, fastest)
cargo install evtx 2>/dev/null || pipx install evtx          # python fallback gives evtx_dump.py

# Chainsaw — sigma-rule hunting over evtx (grab the release binary)
mkdir -p ~/tools && cd ~/tools
git clone https://github.com/WithSecureLabs/chainsaw
# then download the prebuilt binary from its Releases page, OR: cargo build --release
#   chainsaw ships bundled sigma rules + mappings in the repo

# Hayabusa — fast evtx -> timeline with built-in detections (grab the release binary)
git clone https://github.com/Yamato-Security/hayabusa --recursive
# download the prebuilt binary from Releases, then:
#   hayabusa update-rules
```

> **DeepBlueCLI** is PowerShell-only (run on a Windows box/VM): `.\DeepBlue.ps1 -log security` — great quick win for 4625 spray, new users, log clear.

### 0e. Windows registry + artifact parsers

```bash
# RegRipper — profile a hive in one shot
git clone https://github.com/keydet89/RegRipper3.0 ~/tools/regripper
#   perl ~/tools/regripper/rip.pl -r NTUSER.DAT -f ntuser > ntuser.txt

# regipy — scriptable registry parsing (Python)
pipx install regipy[full]
#   registry-dump NTUSER.DAT ; regipy-plugins NTUSER.DAT

# Eric Zimmerman (EZ) tools — the best Windows artifact parsers, cross-platform via .NET
# Install .NET runtime, then grab the .NET6 builds (MFTECmd, PECmd, LECmd, AmcacheParser,
# AppCompatCacheParser, EvtxECmd, SBECmd, RBCmd, RECmd):
#   https://ericzimmerman.github.io/   (download "Get-ZimmermanTools")
# Run on Linux with:  dotnet MFTECmd.dll -f '$MFT' --csv out/   (needs dotnet, see 0h)
# ON THE LINUX PWNBOX, prefer the native replacements in 0h (analyzeMFT, prefetch.py,
# rifiuti2, RegRipper...) — only bother with EZ tools if you want their CSV / Timeline Explorer.

# analyzeMFT — pure-Python $MFT parser (no .NET needed)
pipx install analyzeMFT
```

### 0f. Documents, mail, browsers

```bash
pipx install oletools        # olevba, oleid, rtfobj, mraptor, oledump
pipx install pyhindsight     # browser history/cache (Chrome/Edge/Firefox) -> report
sudo apt install -y pst-utils   # readpst for .pst mailboxes
pipx install extract-msg     # parse Outlook .msg
# peepdf for deep PDF analysis:
git clone https://github.com/jesparza/peepdf ~/tools/peepdf
```

### 0g. Stego / carving extras

```bash
sudo gem install zsteg                    # LSB stego in PNG/BMP
# stegseek — fast steghide bruteforce (download release binary):
#   stegseek file.jpg /usr/share/wordlists/rockyou.txt
wget -O ~/tools/stegsolve.jar http://www.caesum.com/handbook/Stegsolve.jar   # GUI bitplanes
# zbarimg for QR/barcodes:
sudo apt install -y zbar-tools

# audio / image / video forensics + crypto helpers
sudo apt install -y sox audacity multimon-ng ffmpeg imagemagick
pipx install xortool            # XOR key-length/key finder
pipx install stego-lsb          # LSB stego in WAV/PNG  (or: git clone + python3)
```

### 0h. Runtimes & Windows-only-tool fallbacks (you're on a Linux Pwnbox)

Everything above is Linux-native. A few classic artifact parsers are Windows (the EZ tools, DeepBlueCLI). In order of preference: **(1)** use the Linux-native equivalent below — nothing extra to install; **(2)** run the EZ tools' cross-platform `.dll` builds via `dotnet`; **(3)** install a runtime and run the Windows tool.

**Install the runtimes only if you actually need options 2/3:**
```bash
# Rust/cargo — only if you build evtx_dump/chainsaw/mft from source instead of grabbing release binaries
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && source ~/.cargo/env

# .NET runtime — to run EZ tools:  dotnet MFTECmd.dll -f '$MFT' --csv out/
sudo apt install -y dotnet-runtime-8.0 2>/dev/null || { \
  wget https://dot.net/v1/dotnet-install.sh -O /tmp/dn.sh && bash /tmp/dn.sh --channel 8.0 --runtime dotnet; }

# Mono — for NetworkMiner
sudo apt install -y mono-complete

# PowerShell on Linux — only if you want DeepBlueCLI
sudo apt install -y powershell 2>/dev/null || sudo snap install powershell --classic
```

**Windows/.NET tool → Linux-native replacement (no runtime needed — prefer these):**

| Windows tool | Does | Linux-native replacement | Install / run |
| --- | --- | --- | --- |
| MFTECmd | parse `$MFT` | `analyzeMFT.py` / `mft_dump` | `pipx install analyzeMFT` · `cargo install mft` |
| PECmd | prefetch | `prefetch.py` | `pipx install windowsprefetch` |
| LECmd | LNK files | `lnkparse` | `pipx install LnkParse3` |
| JLECmd | jump lists | `LnkParse3` / manual | `pipx install LnkParse3` |
| AppCompatCacheParser | ShimCache | RegRipper `shimcache` | `rip.pl -r SYSTEM -p shimcache` |
| AmcacheParser | Amcache | RegRipper `amcache` / regipy | `rip.pl -r Amcache.hve -p amcache` |
| RBCmd | Recycle Bin | `rifiuti2` | `sudo apt install -y rifiuti2` |
| SBECmd | Shellbags | regipy shellbag plugin | `regipy-plugins UsrClass.dat` |
| RECmd / Registry Explorer | registry | RegRipper / regipy | (see 0e) |
| EvtxECmd | evtx → CSV | Hayabusa / `evtx_dump` | (see 0d) |
| DeepBlueCLI | evtx quick wins | Chainsaw / Hayabusa | (see 0d) |
| FTK Imager | image mount/preview | `ewfmount` + `guestmount` + Autopsy | (0a / 4.1) |
| Timeline Explorer | view CSV timelines | LibreOffice Calc, `csvkit`/`qsv`, Timesketch | `sudo apt install -y libreoffice-calc csvkit` |

> **Last-resort fallback (no egress, pip/apt dead):** every Linux-native tool above is a single Python/Perl/Rust program you can `git clone` and run in place — the repos are in 0b–0g. Clone them on your host beforehand and transfer over the VPN if GitHub is blocked on game day.

### 0i. Wordlists + final sanity check

```bash
# rockyou
sudo gzip -dk /usr/share/wordlists/rockyou.txt.gz 2>/dev/null
ls -la /usr/share/wordlists/rockyou.txt

# verify the heavy hitters resolve (any MISSING = install before game day)
for t in vol tshark mmls fls ewfmount qemu-img guestmount binwalk exiftool \
         olevba steghide zsteg log2timeline.py analyzeMFT.py rifiuti-vista \
         prefetch.py lnkparse hindsight; do
  printf '%-18s ' "$t"; command -v "$t" || echo "MISSING — install before game day"
done
# event-log + registry tools are scripts/binaries, check by path:
for p in ~/tools/chainsaw/chainsaw ~/tools/hayabusa/hayabusa ~/tools/regripper/rip.pl; do
  [ -e "$p" ] && echo "ok   $p" || echo "MISSING $p"
done
```

> Keep all cloned tools under `~/tools/` and add release-binary dirs to `PATH` in `~/.bashrc`. One folder, no hunting mid-challenge.

---

## Game-Day Runbook — literal step-by-step (start here)

Tools are installed. A challenge drops. Do these in order, every time.

**Step 0 — the night before (once):** run 0a–0g, then the 0i sanity loop until nothing says MISSING, and clone the CVE/PoC repos ([05 §1](05-cve-poc-forensics.md)) while you still have internet.

**Step 1 — make a clean workspace and NEVER touch the original.**
```bash
mkdir -p ~/case/chal1/{evidence,out,notes} && cd ~/case/chal1
cp /path/to/given/* evidence/           # copy the downloaded artifacts in
chmod -R a-w evidence/                   # make originals read-only so you can't corrupt them
sha256sum evidence/* | tee notes/hashes.txt   # record hashes (questions sometimes ask)
```

**Step 2 — read ALL the questions first.** Write them into `notes/questions.txt`. Next to each, note the **format** the answer must be (timestamp? SHA256? IP? path? CVE id?). You answer per-question — don't try to "solve" the whole image.

**Step 3 — identify every artifact.**
```bash
file evidence/*          # what each one actually is
exiftool evidence/*      # metadata / software / timestamps
```
Match each to a type using the [§1 triage table](#1-triage--the-first-5-minutes-on-any-artifact). **If `file` says a VM/image container (E01/VMDK/VDI/VHDX/QCOW2/OVA) or `mmls`/`vol` errors with "cannot determine format" → go to [§4.1](#41-containers-forensic-images--vm-files--get-to-a-mountable-form-first) FIRST** and convert/mount it, then come back.

**Step 4 — open the matching branch and run its first commands.** One artifact = one branch:

| It's a… | Jump to | Literal first 3 commands |
| --- | --- | --- |
| Memory dump | [§4a](#4a-windows-memory-dump-memraw--vmem--dmp) | `vol -f evidence/mem.raw windows.info` → `windows.pstree` → `windows.cmdline` |
| Windows disk | [§4b](#4b-windows-disk-image-e01--vmdk--img) | `mmls` → mount `-o ro` → `log2timeline.py` |
| pcap | [§4c](#4c-network-capture-pcap--pcapng) | `tshark -r f -q -z io,phs` → `--export-objects http,out/` → Follow Stream |
| Event logs | [§4d](#4d-windows-event-logs-evtx) | `hayabusa csv-timeline -d evidence/ -o out/tl.csv` → sort it |
| Linux disk | [§4e](#4e-linux-server-compromise-disk-image--triage-tarball) | mount `-o ro` → grep web logs → `.bash_history` |
| Doc / PDF / email | [§4f](#4f-malicious-document--phishing-docx-doc-xlsm-pdf-eml) | `oleid`/`olevba` or `pdfid` → decode the payload URL |
| Browser profile | [§4g](#4g-browser-artifacts-history--downloads--cache) | `hindsight -i <profile> -o out/browser` |
| Mobile backup | [§4h](#4h-mobile-backup-android--ios) | `aleapp.py`/`ileapp.py -i evidence/ -o out/` |
| Image/audio/archive/blob | [§2](#2-standalone-file--stego-analysis) | `file` → `binwalk -e` / `zsteg -a` / `exiftool` |

**Step 5 — work the question list top-down**, pulling the answer from that branch's table. Write every finding into `notes/` as you go (IP, user, filename, hash, timestamp, command, CVE/MITRE).

**Step 6 — more than one artifact? Build ONE timeline and correlate.** Pivot on a shared time + IOC → [§4i](#4i-correlate-across-artifacts-when-you-get-more-than-one).

**Step 7 — "which vulnerability / CVE did they use?"** Match the payload signature, then look it up → [05-cve-poc-forensics.md](05-cve-poc-forensics.md).

**Step 8 — submit each answer in the EXACT format** ([§6](#6-answer-format-discipline--common-question-patterns)). Re-check timezones on timestamps and algorithm on hashes before you hit submit.

**Step 9 — stuck on a question?** Run this fallback, in order, before moving on:
```bash
strings -n 8 evidence/artifact | grep -iE 'flag|nexsec26\{|password|http'   # cheap wins
binwalk -e evidence/artifact                                                 # hidden embedded files
exiftool -a -G1 evidence/artifact                                            # overlooked metadata
# then: throw any odd blob into CyberChef "Magic"; try a different tool for the same artifact
```
Still stuck after ~10 min → **skip it, bank the ones you can answer, come back.** Points are per-question.

---

## 1. Triage — the first 5 minutes on any artifact

**Always do this before picking a specialist tool.** It tells you *which* walkthrough in Section 4 to run.

```bash
file *                                   # true type of every artifact
exiftool <artifact>                      # metadata, software, timestamps
sha256sum <artifact>                     # match any hash the brief gives you
ls -la                                   # sizes hint at type (multi-GB = disk/mem; KB = doc)
```

Map the `file` output to the walkthrough:

| `file` says / extension | It's a... | Go to |
| --- | --- | --- |
| `Microsoft Word/Excel`, `Composite Document`, `Zip` with `word/` | Office doc / maldoc | **4f** |
| `PDF document` | PDF | **4f** |
| `pcap`, `pcapng`, `tcpdump capture` | Network capture | **4c** |
| `MS Windows registry` / named `NTUSER.DAT`, `SYSTEM`, `SOFTWARE` | Registry hive | **4b** |
| `MS Windows Vista Event Log` / `.evtx` | Event logs | **4d** |
| `DOS/MBR boot sector`, `.E01`, `.vmdk`, `.img`, `.raw` (huge) | Disk image | **4b** (Win) / **4e** (Linux) |
| `data` (huge) + brief says "memory" / `.mem` `.vmem` `.dmp` `.lime` | Memory dump | **4a** |
| image/audio/video | Stego / embedded | Section 2 |

If `file` says `data` and it's small, it's probably encoded/encrypted — `strings`, `binwalk`, then CyberChef.

---

## 2. Standalone File & Stego Analysis

(Small given files: images, audio, archives, documents, or an encoded blob — the kind dropped straight into a forensics challenge.)

**First move on any file — identify before anything else:**
```bash
file <f>; xxd <f> | head          # magic bytes vs extension
binwalk <f>                        # embedded files/firmware
binwalk -e <f>                     # extract embedded content (into _<f>.extracted/)
exiftool <f>                       # metadata (GPS, author, software, comments)
strings -n 8 <f> | less            # readable text; grep for flag{ or creds
strings -e l <f>                   # 16-bit little-endian (Windows wide strings)
```

**Image steganography**
```bash
steghide info <f>; steghide extract -sf <f>      # try blank pass, then wordlist
stegseek <f> /usr/share/wordlists/rockyou.txt    # fast steghide brute
zsteg -a <f>.png                                 # all LSB methods on PNG/BMP
outguess -r <f> out.txt
pngcheck -v <f>                                  # corrupted/appended chunks
java -jar ~/tools/stegsolve.jar                  # GUI bit-plane viewer
```
- Compare declared image dimensions vs real size → hidden data after `IEND`.
- Fix corrupted headers (wrong magic bytes) by hand in `xxd`/hexedit.

**Archive / carving**
```bash
binwalk -e <f>; foremost -i <f> -o out/; photorec <f>
bulk_extractor -o out/ <f>                       # carves emails, URLs, ccns, etc.
zip2john <f> > hash.txt && john hash.txt          # crack zip password
```

**Encoding / crypto quick checks**
```bash
echo '<string>' | base64 -d
echo '<hex>' | xxd -r -p
# CyberChef "Magic" wand auto-detects encoding chains (base64/32/58/85, hex, ROT, XOR, gzip)
```
A long base64-looking blob inside a pcap / memdump / image is very often the flag, double- or triple-encoded.

**Audio forensics** (WAV/MP3/FLAC — a whole CTF category)
```bash
exiftool a.wav; strings a.wav | grep -i flag
sox a.wav -n spectrogram -o spec.png     # LOOK at the spectrogram — flags/text hidden here
audacity a.wav                           # GUI: Spectrogram view, split stereo, reverse, slow down
# common tricks to check:
#  - text drawn in the SPECTROGRAM (most common)
#  - Morse code (listen / read the waveform:  -.-.  )
#  - DTMF phone tones -> decode:  multimon-ng -a DTMF -t wav a.wav
#  - data in ONE stereo channel, or L-R difference
#  - reversed / slowed / sped-up audio
#  - LSB stego in samples:  check with WavSteg / stego-lsb
multimon-ng -a DTMF -a MORSE_CW -t wav a.wav
```

**Image / video deep checks** (beyond §stego above)
```bash
exiftool -gps:all -a img.jpg             # GPS coords -> geolocation answers
convert img.jpg -auto-level out.png      # ImageMagick: pull faint detail
ffmpeg -i clip.mp4 frames/%04d.png       # split video to frames, then scan each
ffmpeg -i clip.mp4 -vn audio.wav         # rip the audio track -> audio forensics above
zbarimg img.png                          # decode QR / barcodes in an image
# a GIF: split frames, a frame may hold the flag:  convert anim.gif frame_%03d.png
```

**Encoding & classical crypto** (when `file` says `data` / you have a short blob)
```bash
# Try, in order: base64 -> base32 -> hex -> ROT/Caesar -> XOR -> gzip/zlib
echo '<s>' | base64 -d ; echo '<s>' | base32 -d ; echo '<s>' | xxd -r -p
# CyberChef "Magic" auto-detects the chain; feed it the blob first.
# Classical ciphers (quipqiup.com for substitution, dcode.fr for everything):
#   Caesar/ROT, Vigenère, XOR (single/multi-byte), Atbash, rail-fence,
#   Base58/85, morse, binary, baudot, brainfuck, substitution.
xortool blob.bin                         # find XOR key length + key
```

**File repair / format triage** (broken or disguised files)
```bash
file f; xxd f | head                     # does the magic match the extension?
#   fix a wrong header by editing magic bytes:  PNG=89504E47  JPG=FFD8FF  PDF=25504446
#   GZIP=1F8B  ZIP/Office/JAR=504B0304  PK  ELF=7F454C46  RAR=526172
binwalk -e f                             # pull embedded files out of a container
pngcheck -v f; zip -FF broken.zip --out fixed.zip   # repair truncated zip
```

**OSINT / geolocation** (an image/doc is the artifact, the answer is "where/who/when")
```bash
exiftool -a -G1 artifact                 # author, software, serial, GPS, timestamps
#  - GPS -> paste lat,long into a map
#  - reverse image search (Google/Yandex/TinEye) for location/source
#  - landmarks, signage, license plates, sun angle -> narrow the place
#  - document author/company + revision history (docProps/core.xml)
```

---

## 3. Artifact Analysis — tool map by type

Triage order: `file` + `exiftool` + `sha256sum` → pick the row → **work the question list, don't try to "solve" the whole artifact.**

| Artifact type | Primary tools | What to look for |
| --- | --- | --- |
| Disk image (.img/.E01/.vmdk) | Autopsy, FTK Imager, `mmls`/`fls`/`icat`, EZ tools, RegRipper | Deleted files, recent docs, browser history, Run keys, Recycle Bin, $MFT timeline |
| Memory dump (.mem/.vmem/.dmp/.lime) | Volatility 3, Volatility 2 | Process tree, command lines, net connections, injected code, dumped files, in-memory hives, console history |
| Network capture (.pcap/.pcapng) | Wireshark, tshark, NetworkMiner, Zeek | Credentials, exfil, C2 beacon, DNS tunneling, extracted files/objects |
| Windows Event Logs (.evtx) | EvtxECmd, Chainsaw, Hayabusa, `evtx_dump`, DeepBlueCLI | 4624/4625 logon, 4688 proc-create, 4720 user-add, 1102 log-clear, 4104 PowerShell |
| Windows registry (hives) | RegRipper, regipy, Registry Explorer | Run keys, USBSTOR, UserAssist, ShimCache/Amcache, TypedPaths, SAM |
| Browser artifacts | pyhindsight, DB Browser for SQLite | History/Downloads/Cookies DBs, cache, session/localStorage |
| Email (.eml/.pst/.msg) | `readpst`, `extract-msg`, header inspection | Received / X-Originating-IP, SPF/DKIM, attachments, reply-to mismatch |
| Office docs (.docx/.xlsx/.pptx/.doc) | oletools (`olevba`,`oleid`,`oledump`), `unzip` | VBA macros, embedded objects, `docProps/core.xml`, remote templates |
| PDF | `pdfid`, `pdf-parser`, peepdf, `qpdf` | JavaScript, embedded files, `/OpenAction`, `/Launch`, revisions |
| Mobile (Android/iOS backup) | ALEAPP/iLEAPP, `adb`, sqlite browser | SMS/call DBs, app data, shared_prefs, WAL (freshest data) |

---

## 4. Full Incident Walkthroughs

This is **one walkthrough that starts the moment you know what the artifact is.** Run the master flow below on every challenge, branch into the matching artifact section (4a–4h), then correlate across artifacts (4i). Each branch is framed as **"the question they'll ask → the command → where the answer is."**

### 4.0 Master flow — run this for any artifact, every time

```
┌─ 1. IDENTIFY ──────────────────────────────────────────────┐
│  file * ; exiftool <a> ; sha256sum <a>                      │
│  → match the type against the Section 1 table               │
└─────────────────────────────────────────────────────────────┘
          │
┌─ 2. READ THE QUESTIONS FIRST ──────────────────────────────┐
│  Note what each answer must be (timestamp? hash? IP? path?) │
│  Answer only what's asked — points are per-question.        │
└─────────────────────────────────────────────────────────────┘
          │
┌─ 3. BRANCH BY ARTIFACT TYPE ───────────────────────────────┐
│  memory → 4a   disk/Win → 4b   pcap → 4c   evtx → 4d        │
│  Linux box → 4e   maldoc/mail → 4f   browser → 4g           │
│  mobile → 4h   registry hive → 4b(reg)   image/audio → §2   │
└─────────────────────────────────────────────────────────────┘
          │
┌─ 4. EXTRACT IOCs AS YOU GO ────────────────────────────────┐
│  Running notes table: user, IP, domain, filename, hash,     │
│  timestamp, command, MITRE technique.                       │
└─────────────────────────────────────────────────────────────┘
          │
┌─ 5. CORRELATE (if >1 artifact) → 4i ───────────────────────┐
│  Most incidents hand you 2-3 artifacts that reference each  │
│  other. Build ONE timeline so the story lines up.           │
└─────────────────────────────────────────────────────────────┘
          │
┌─ 6. ANSWER IN EXACT FORMAT → §6 ───────────────────────────┘
```

**Decision table — "I've confirmed the artifact is X, now what":**

| Confirmed artifact | Open with | Branch |
| --- | --- | --- |
| Memory dump (Win/Linux) | Volatility 3 | **4a** |
| Disk image, Windows (.E01/.vmdk/.img) | ewfmount + TSK + EZ tools | **4b** |
| Standalone registry hive | RegRipper / regipy | **4b** (registry block) |
| Windows event logs (.evtx) | Hayabusa / Chainsaw | **4d** |
| Network capture (.pcap/.pcapng) | tshark / Zeek / NetworkMiner | **4c** |
| Disk image / tarball, Linux | mount -o ro + log grep | **4e** |
| Office doc / PDF / email | oletools / pdf-parser / headers | **4f** |
| Browser profile / SQLite DBs | pyhindsight | **4g** |
| Mobile backup (Android/iOS) | ALEAPP / iLEAPP | **4h** |
| Image / audio / archive / encoded blob | binwalk / zsteg / steghide / CyberChef | **§2** |
| Forensic image / VM container (.E01, .vmdk, .vdi, .vhdx, .qcow2, .ova, .vmem…) | convert/mount first | **4.1** |

> If `mmls`/`vol` errors with "cannot determine format", you've been handed a **container**, not a raw image — go to 4.1, convert or mount it to a raw/analyzable form, then come back to the right branch.

### 4.1 Containers, forensic images & VM files — get to a mountable form first

You rarely get a clean `.raw`. Most challenges hand you a forensic-image or VM container. **Identify it, then expose it as a raw image (or mount it read-only), then run 4a/4b/4e on the result.**

**Install the format tools (add to Section 0):**
```bash
sudo apt install -y ewf-tools afflib-tools libvmdk-utils libvhdi-utils \
                    libvslvm-utils qemu-utils libguestfs-tools nbd-client
```

**Always identify the container first:**
```bash
file image.*                     # first guess
qemu-img info disk.vmdk          # VM disks: real format, virtual size, backing file
ewfinfo image.E01                # EWF/EnCase metadata (acquiry info, hashes)
mmls disk.img                    # if THIS works, it's already raw -> go straight to 4b/4e
```

#### Disk / forensic-image formats

| Format (ext) | Expose it as raw / mount read-only |
| --- | --- |
| **raw / dd** (`.img .raw .dd .001`) | already raw — `mmls disk.img` directly |
| **EWF / EnCase** (`.E01 .Ex01 .s01`) | `ewfmount img.E01 /mnt/ewf` → `/mnt/ewf/ewf1` (raw). Or convert: `ewfexport -t out img.E01` |
| **AFF** (`.aff`) | `affuse img.aff /mnt/aff` → `/mnt/aff/img.aff.raw` |
| **VMDK** (VMware) | `qemu-img convert -O raw disk.vmdk disk.raw`  •or•  `vmdkmount disk.vmdk /mnt/vmdk` |
| **VDI** (VirtualBox) | `qemu-img convert -O raw disk.vdi disk.raw` |
| **VHD / VHDX** (Hyper-V) | `qemu-img convert -O raw disk.vhdx disk.raw`  •or•  `vhdimount disk.vhdx /mnt/vhd` |
| **QCOW2** (QEMU/KVM) | `qemu-img convert -O raw disk.qcow2 disk.raw` |
| **OVA** (`.ova`) | it's a tar: `tar xvf vm.ova` → yields `.ovf` + `.vmdk`(s), then handle the vmdk above |
| **OVF** (`.ovf`) | XML descriptor; the real disks are the `.vmdk`/`.vhd` files beside it |

**Universal method A — qemu-nbd (any VM disk, no conversion/space needed):**
```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd -r -c /dev/nbd0 disk.vmdk      # -r = read-only; works for vmdk/vdi/vhdx/qcow2
sudo partprobe /dev/nbd0
mmls /dev/nbd0                                 # partition table
sudo mount -o ro /dev/nbd0p2 /mnt/vm          # mount the data partition
# ...analyze under /mnt/vm...
sudo umount /mnt/vm && sudo qemu-nbd -d /dev/nbd0   # clean up
```

**Universal method B — libguestfs (auto-detects format AND partitions):**
```bash
virt-filesystems -a disk.vmdk --long -h       # list partitions/filesystems first
guestmount -a disk.vmdk -i --ro /mnt/vm       # -i inspects + mounts the OS automatically
#   specific partition:  guestmount -a disk.img -m /dev/sda1 --ro /mnt/vm
guestfish --ro -a disk.vmdk -i                 # interactive shell when you just need a few files
```

**TSK directly on a container** (if built with the libs — skips conversion):
```bash
mmls -i ewf img.E01            # EWF
mmls -i vmdk disk.vmdk         # VMDK
fls  -i vmdk -r -o <off> disk.vmdk
```

Once you have the raw image or a mounted filesystem → **Windows disk = 4b, Linux disk = 4e.**

#### VM memory / saved-state files → Volatility

| File (ext) | How to feed Volatility |
| --- | --- |
| **VMware RAM** (`.vmem`) | raw physical memory — `vol -f vm.vmem windows.info` directly (keep the `.vmsn`/`.vmss` beside it for metadata) |
| **VMware snapshot/suspend** (`.vmsn .vmss`) | convert with VMware's `vmss2core -W vm.vmss vm.vmem`, then run vol on the `.vmem` |
| **VirtualBox saved state** | `VBoxManage debugvm "<vm>" dumpvmcore --filename mem.elf` → `vol -f mem.elf linux.pslist` (ELF core) |
| **Windows crash dump** (`.dmp`) | vol reads it directly: `vol -f memory.dmp windows.info` |
| **Hibernation** (`hiberfil.sys`) | convert with `hibr2bin hiberfil.sys mem.raw` (Comae), then run vol on `mem.raw` |
| **Pagefile** (`pagefile.sys`) | supplementary — carve with `bulk_extractor`/`strings`, correlate with the memory dump |

> If you get a **whole VM folder**, the `.vmdk` is the disk (→ 4.1 disk method) and the `.vmem`/`.vmss` is the RAM (→ 4a). You can often answer the same question from either — pick whichever the question points at.

#### Other containers you might be handed

- **Triage collections** (KAPE / Velociraptor output, a `.zip`/`.tar.gz` of pulled artifacts): just extract and feed each file to its parser (evtx→4d, hives→4b, browser DBs→4g). No mounting needed.
- **LVM / BitLocker / LUKS volumes:** after exposing the disk, `vgscan && vgchange -ay` for LVM; `dislocker` for BitLocker; `cryptsetup open` for LUKS — then mount the inner filesystem.
- **Single files pulled from a case** (a lone registry hive, one evtx, a SQLite DB): skip all of the above and go straight to the matching branch.

### 4a. Windows memory dump (`mem.raw` / `.vmem` / `.dmp`)

**Scenario:** "Analyze the memory image from the compromised workstation and answer the IR questions."

```bash
# 0. Identify the image (OS build, confirms vol can parse it)
vol -f mem.raw windows.info
```

| Question they ask | Command | Where the answer is |
| --- | --- | --- |
| OS version / build / profile | `windows.info` | `NtMajorVersion`, `NtBuildNumber` |
| What processes were running | `windows.pstree` | Full parent→child tree; note odd parents |
| The suspicious / malicious process | `windows.pstree` then `windows.malfind` | `winword.exe→cmd.exe→powershell.exe`, or unsigned proc in temp |
| Exact command line run | `windows.cmdline` | Full argv per PID — often the flag or the download URL |
| PID / PPID of the malware | `windows.pslist` / `windows.psscan` | `psscan` also finds **hidden/terminated** procs |
| Attacker C2 IP / port | `windows.netscan` | ForeignAddr + owning PID; cross-ref to the bad process |
| Injected / hollowed code | `windows.malfind -D out/` | MZ header in `PAGE_EXECUTE_READWRITE` region = injected; dumps it |
| What command history / typed | `windows.cmdline`, `windows.consoles`, `windows.cmdscan` | `consoles` recovers full console scrollback incl. output |
| Files the attacker touched | `windows.filescan \| grep -i <kw>` | Get the virtual offset, then dump (below) |
| Pull a file out of memory | `windows.dumpfiles --virtaddr <offset> -o out/` | Carved file in `out/` |
| Dump a whole process | `windows.memmap --pid <pid> --dump -o out/` | `pid.<pid>.dmp` → run `strings`/AV on it |
| Local password hashes | `windows.hashdump` / `windows.lsadump` / `windows.cachedump` | NTLM hashes → crack `-m 1000` |
| Persistence (registry in RAM) | `windows.registry.printkey --key 'Software\Microsoft\Windows\CurrentVersion\Run'` | Auto-run values |
| Clipboard contents | `windows.clipboard` | Sometimes holds the pasted password/flag |
| What the user ran recently | `windows.registry.userassist` | GUI program execution counts + timestamps |

**Pull-it-together recipe:**
```bash
vol -f mem.raw windows.pstree          > out/pstree.txt   # find the odd process + its PID
vol -f mem.raw windows.cmdline         > out/cmdline.txt  # read its exact command line
vol -f mem.raw windows.netscan         > out/net.txt      # map that PID to a C2 address
vol -f mem.raw windows.malfind -D out/                     # dump injected regions
vol -f mem.raw windows.consoles        > out/consoles.txt # recover shell scrollback
vol -f mem.raw windows.filescan | grep -iE 'flag|\.ps1|\.exe|\.zip|desktop' > out/files.txt
vol -f mem.raw windows.dumpfiles --virtaddr <offset> -o out/
strings out/*.dmp | grep -iE 'flag\{|http|password'
```

**Linux memory dump:** same plugin names under `linux.*` — but you need an **ISF symbol table matching the exact kernel**. vol3 often auto-fetches it; if not, build one with `dwarf2json` against the target kernel's debug symbols and drop it in `volatility3/symbols/linux/`.
```bash
vol -f mem.lime linux.pslist
vol -f mem.lime linux.bash          # recover bash history straight from RAM (great for "what commands")
vol -f mem.lime linux.psaux         # full process args
vol -f mem.lime linux.malfind
vol -f mem.lime linux.lsof          # open files/sockets
```

### 4b. Windows disk image (`.E01` / `.vmdk` / `.img`)

**Scenario:** "Here's a triage image / full disk from the host. When did they get in, what did they run, what did they take?"

```bash
# .E01? mount the EWF first so TSK sees a raw image:
mkdir /mnt/ewf && ewfmount evidence.E01 /mnt/ewf      # exposes /mnt/ewf/ewf1
IMG=/mnt/ewf/ewf1        # (for .img/.raw just: IMG=disk.img)

mmls "$IMG"                        # partition table -> note the Windows partition start offset
OFF=<offset>                       # sector offset of the NTFS partition
fls -r -o $OFF "$IMG" | less       # recursive file listing (deleted files show as * )
icat -o $OFF "$IMG" <inode> > out/file   # extract one file by inode
tsk_recover -o $OFF "$IMG" out/recovered/ # bulk-recover deleted/live files
```

Prefer mounting read-only to run parsers against real paths:
```bash
sudo mount -o ro,loop,offset=$((OFF*512)) "$IMG" /mnt/disk
```

| Question | Where / command |
| --- | --- |
| Full activity timeline | `log2timeline.py out.plaso /mnt/disk && psort.py -o l2tcsv out.plaso -w timeline.csv` → open in Timeline Explorer / sort by time |
| Programs executed (even if deleted) | **Prefetch**: `prefetch.py -f /mnt/disk/Windows/Prefetch/*.pf` • **ShimCache**: `rip.pl -r SYSTEM -p shimcache` • **Amcache**: `rip.pl -r Amcache.hve -p amcache` _(EZ-tool alt via dotnet: `PECmd`/`AppCompatCacheParser`/`AmcacheParser`)_ |
| Persistence | RegRipper `SOFTWARE` (Run/RunOnce), Scheduled Tasks `\Windows\System32\Tasks`, Services, Startup folder |
| User accounts / new admin | RegRipper `SAM` → users & groups; correlate with event log 4720 |
| USB devices plugged in | `rip.pl -r SYSTEM -p usbstor` + `SOFTWARE` → USB serials & first/last connect |
| Recently opened files | `NTUSER.DAT` → RecentDocs, `rip.pl -r NTUSER.DAT -p recentdocs` |
| What user typed in Run / Explorer | `NTUSER.DAT` → RunMRU, TypedPaths |
| Deleted files | `tsk_recover`, or Recycle Bin: `rifiuti-vista /mnt/disk/'$Recycle.Bin'/*` _(EZ alt: `RBCmd`)_ |
| Browser history / downloads | `hindsight -i /mnt/disk/Users/<u>/AppData/Local/Google/Chrome/User\ Data/Default -o out/browser` |
| $MFT timeline / file creation times | `analyzeMFT.py -f '/mnt/disk/$MFT' -c out/mft.csv` _(EZ alt: `MFTECmd`)_ → look for timestomping (0-ns `$STD_INFO` vs `$FILE_NAME` mismatch) |
| Credentials | `SAM`+`SYSTEM` → `secretsdump.py -sam SAM -system SYSTEM LOCAL` |

**Registry hive locations on the mounted image:**
```
/mnt/disk/Windows/System32/config/SYSTEM, SOFTWARE, SAM, SECURITY
/mnt/disk/Users/<user>/NTUSER.DAT
/mnt/disk/Users/<user>/AppData/Local/Microsoft/Windows/UsrClass.dat   (shellbags)
```
Quick full profile of any hive: `perl ~/tools/regripper/rip.pl -r <hive> -a > hive_report.txt`

### 4c. Network capture (`.pcap` / `.pcapng`)

**Scenario:** "Traffic was captured during the intrusion. Find the attacker, what they stole, and the C2."

```bash
# Auto-extract everything first — fastest win
mkdir -p out && mono NetworkMiner.exe capture.pcap   # GUI (needs mono, 0h); or skip it and use tshark/Zeek below
tshark -r capture.pcap --export-objects http,out/http/   # carve all HTTP transfers
tshark -r capture.pcap --export-objects smb,out/smb/
zeek -r capture.pcap                              # generates conn.log, dns.log, http.log, files.log
```

| Question | tshark / Wireshark filter |
| --- | --- |
| Who talked to whom (top talkers) | Wireshark → Statistics → Conversations; or `tshark -r f -q -z conv,ip` |
| Protocols present | Statistics → Protocol Hierarchy; `tshark -r f -q -z io,phs` |
| Cleartext credentials | `http.request.method=="POST"`, `ftp`, `telnet`, `imap`/`pop`; NetworkMiner "Credentials" tab |
| Follow one conversation | right-click → Follow → TCP/HTTP Stream; `tcp.stream eq 0` |
| Files transferred | `--export-objects http,out/` / Zeek `files.log` + `extract_files` |
| DNS exfil / tunneling | `dns` → long/odd subdomains, high query volume to one domain; `tshark -r f -T fields -e dns.qry.name 'dns'` |
| C2 beacon | fixed-interval connects to one IP — Statistics → IO Graph, or sort Zeek `conn.log` by `ts` per dest |
| What was downloaded/run | HTTP GET to `.exe/.ps1/.sh`; follow the stream, carve the body, `file`/`strings` it |
| Data exfiltrated | large outbound `POST`/FTP `STOR`; check `conn.log` `orig_bytes` |
| Decrypt HTTPS | only if a `SSLKEYLOGFILE` is provided: Wireshark → Preferences → TLS → (Pre)-Master-Secret log |

**Useful one-liners:**
```bash
tshark -r f.pcap -Y 'http.request' -T fields -e ip.src -e http.host -e http.request.uri   # all requested URLs
tshark -r f.pcap -Y 'ftp' -T fields -e ftp.request.command -e ftp.request.arg             # FTP commands + creds
tshark -r f.pcap -Y 'dns' -T fields -e dns.qry.name | sort | uniq -c | sort -rn | head     # top DNS names
tshark -r f.pcap --export-objects http,out/ ; ls -la out/ ; file out/*                     # grab + ID every HTTP object
```
A base64 blob inside an HTTP body or a DNS TXT record is usually staged payload or exfil — decode it.

### 4d. Windows event logs (`.evtx`)

**Scenario:** "Given the Security/System/PowerShell logs, reconstruct the attack."

```bash
# Fastest path: Hayabusa timeline with built-in detections
hayabusa csv-timeline -d ./evtx/ -o out/timeline.csv       # then open/sort in Timeline Explorer

# Sigma-rule hunt with Chainsaw (bundled rules + mappings)
chainsaw hunt ./evtx/ -s sigma/ --mapping mappings/sigma-event-logs-all.yml -r rules/ --csv out/

# Targeted search without rules
chainsaw search -t 'Event.System.EventID: 4625' ./evtx/      # failed logons
evtx_dump Security.evtx | less                               # raw XML when you need a specific field
```

**Event IDs that answer the usual questions:**

| Question | Log | Event ID | Field to read |
| --- | --- | --- | --- |
| Successful logon / lateral move | Security | **4624** | `LogonType` (3=net, 10=RDP), `TargetUserName`, `IpAddress` |
| Password spray / brute force | Security | **4625** | count by `TargetUserName` / `IpAddress` |
| Explicit-cred use (runas/pivot) | Security | **4648** | `Subject` → `Target` user mismatch |
| Process execution | Security | **4688** | `NewProcessName`, `CommandLine` (if audit enabled), parent |
| New user created | Security | **4720** | `TargetUserName` |
| User added to admin group | Security | **4732/4728** | `MemberSid`, `TargetUserName` (group) |
| Service installed (persistence) | System | **7045** | `ServiceName`, `ImagePath` |
| Scheduled task created | Security | **4698** | task name + action |
| **Log cleared** (anti-forensics) | Security | **1102** | who cleared + when |
| PowerShell script block | PowerShell/Operational | **4104** | full (often deobfuscated) script — frequently the payload |
| PowerShell command | PowerShell | **4103** | pipeline + params |
| WMI persistence | WMI-Activity | **5861** | consumer/filter |
| RDP session | TerminalServices | **1149 / 21** | source IP, username |

**Attack reconstruction order:** 4625 (how they got the creds) → 4624 Type 3/10 (first successful logon + source IP) → 4688/4104 (what they ran) → 7045/4698/4720 (persistence they planted) → 1102 (did they cover tracks). Note the **first** and **last** timestamps — questions love "initial compromise time" and "how long were they in."

> **If you see a Sysmon log** (`Microsoft-Windows-Sysmon/Operational`) — start there, it's far richer than Security: **1** process create (with SHA/MD5 hash + full cmdline + parent), **3** network connection, **7** image/DLL load, **8** CreateRemoteThread (injection), **10** process access, **11** file create, **12/13/14** registry, **15** file stream (download mark-of-the-web), **22** DNS query, **23/26** file delete. One Sysmon EID 1 line often answers "what ran / its hash / its parent" in one go.

### 4e. Linux server compromise (disk image / triage tarball)

**Scenario:** "This Linux web server was popped. Find the webshell, the entry point, and persistence."

```bash
# Mount the image read-only (find the right partition with mmls first)
sudo mount -o ro,loop,offset=$((OFF*512)) disk.img /mnt/lin
```

| Question | Where |
| --- | --- |
| Entry point (web exploit) | `/var/log/apache2/access.log` / `nginx/access.log` — grep for `POST`, `.php?`, `?cmd=`, `/uploads/`, long querystrings, 200s on odd paths |
| The webshell file | `find /mnt/lin/var/www -name '*.php' -newermt '<date>'`; grep for `system(`, `eval(`, `base64_decode(`, `passthru(`, `$_GET`/`$_POST\[` |
| Commands the attacker ran | `~/.bash_history`, `/root/.bash_history`, `/home/*/.bash_history` (and `linux.bash` if you also have RAM) |
| When / who logged in | `/var/log/auth.log` (`Accepted password/publickey`, `sudo`), `last -f /mnt/lin/var/log/wtmp`, `lastb` for failures |
| New users / backdoor accounts | `/etc/passwd` (UID 0 besides root? new users?), `/etc/shadow`, `/etc/sudoers`, `/etc/sudoers.d/` |
| Persistence | `crontab -l`, `/etc/cron*`, `/etc/systemd/system/*.service`, `~/.ssh/authorized_keys` (added key!), `/etc/rc.local`, `.bashrc`/`.profile` |
| SUID backdoor | `find /mnt/lin -perm -4000 -type f 2>/dev/null` → compare against a known-good baseline |
| Modified system binaries | `find /mnt/lin -newermt '<date>' -type f 2>/dev/null \| grep -E '/bin/\|/sbin/\|/usr/bin/'` |
| Dropped tools / staging | `/tmp`, `/dev/shm`, `/var/tmp` — common payload drop dirs |
| Exfil | outbound in logs, large files in `/tmp`, `.tar.gz`/`.zip` recently created |

**Fast triage one-liners:**
```bash
grep -riE 'eval\(|base64_decode\(|system\(|passthru\(|shell_exec\(' /mnt/lin/var/www | head
find /mnt/lin -newermt '2026-11-24 00:00' ! -newermt '2026-11-26 00:00' -type f 2>/dev/null   # files changed in the incident window
cat /mnt/lin/home/*/.ssh/authorized_keys /mnt/lin/root/.ssh/authorized_keys 2>/dev/null       # planted keys
awk -F: '$3==0{print}' /mnt/lin/etc/passwd                                                     # extra UID-0 accounts
```

### 4f. Malicious document / phishing (`.docx`, `.doc`, `.xlsm`, `.pdf`, `.eml`)

**Scenario:** "A user opened this attachment. What does it do, and what's the C2/payload URL?"

**Office (macro) documents:**
```bash
oleid  suspicious.doc                 # risk overview (macros, embedded, exploits)
olevba suspicious.doc                 # dumps + deobfuscates VBA; flags AutoOpen, Shell, URLs
olevba --deobf --decode suspicious.doc
oledump.py suspicious.doc             # stream list; -s <n> -v to dump a specific macro stream
# .docx with a remote template injection (no macro):
unzip -o suspicious.docx -d docx/ && grep -r "Target=" docx/word/_rels/   # external template/URL
```
Answers live in: `AutoOpen`/`Document_Open` (trigger), `Shell`/`CreateObject("WScript.Shell")` (execution), and any `http(s)://` string or base64 blob (the payload URL — decode it).

**PDF:**
```bash
pdfid suspicious.pdf                  # counts /JS /JavaScript /OpenAction /Launch /EmbeddedFile
pdf-parser --search JavaScript suspicious.pdf
pdf-parser -o <obj> -f suspicious.pdf # dump + filter-decode a specific object
peepdf -i suspicious.pdf              # interactive; 'js_analyse' to extract scripts
```

**Email headers (`.eml`/`.msg`):**
```bash
extract-msg suspicious.msg            # -> .eml + attachments
# Read these headers top-to-bottom:
#   Received:            -> trace the real sending IP (bottom-most external hop)
#   Return-Path/From     -> spoof mismatch vs envelope
#   Authentication-Results -> SPF/DKIM/DMARC pass/fail
#   X-Originating-IP     -> true source
```
Then run every attachment back through the doc/PDF steps above, and defang + submit URLs/hashes as the questions ask.

**Record IOCs as you go:** sender IP, URL/domain, dropped filename, SHA256 of each stage, MITRE technique. Section 6 covers the format.

### 4g. Browser artifacts (history / downloads / cache)

**Scenario:** "What did the user search, download, or visit?" — given a Chrome/Edge/Firefox profile or its SQLite DBs.

```bash
# One-shot report across all installed browsers in a profile path:
hindsight -i "/path/to/Chrome/User Data/Default" -o out/browser
#   -> out/browser.xlsx : history, downloads, cookies, autofill, timeline

# Manual, when you only have the DB files:
sqlite3 History "SELECT datetime(last_visit_time/1000000-11644473600,'unixepoch'), url \
  FROM urls ORDER BY last_visit_time DESC LIMIT 50;"      # Chrome visit history
sqlite3 History "SELECT target_path, tab_url, total_bytes FROM downloads;"   # downloads
sqlite3 places.sqlite "SELECT datetime(last_visit_date/1000000,'unixepoch'), url \
  FROM moz_places ORDER BY last_visit_date DESC LIMIT 50;"  # Firefox
```

| Question | Where |
| --- | --- |
| Sites visited + when | `urls` / `moz_places` tables (note the epoch conversion above) |
| What they downloaded | `downloads` table → `target_path`, source `tab_url` |
| Search terms | `keyword_search_terms` (Chrome); URL query strings |
| Logged-in accounts | `cookies`, `Login Data` (encrypted — note the account, not the pw) |
| Cached payload / page | cache dir → carve with `file`/`strings`, or `chromagnon`/`hindsight` |

> Chrome timestamps are microseconds since **1601-01-01** (subtract 11644473600 after /1e6); Firefox is microseconds since **1970**. Get this wrong and every timestamp answer is off.

### 4h. Mobile backup (Android / iOS)

**Scenario:** "Here's a phone extraction / backup — recover messages, locations, app activity."

```bash
# Automated parsers turn a raw extraction into a browsable report:
python3 aleapp.py  -t fs   -i extraction/ -o out/android     # Android (ALEAPP)
python3 ileapp.py  -t fs   -i extraction/ -o out/ios         # iOS (iLEAPP)

# Manual SQLite dives (freshest data often lives in -wal, so copy the whole set):
sqlite3 mmssms.db "SELECT address, datetime(date/1000,'unixepoch'), body FROM sms;"   # Android SMS
sqlite3 sms.db    "SELECT text, datetime(date/1000000000+978307200,'unixepoch') FROM message;"  # iOS iMessage
```

| Question | Where |
| --- | --- |
| SMS / chat messages | `mmssms.db` (Android), `sms.db` (iOS), app DBs for WhatsApp/Signal |
| Call log | `calllog.db` / `CallHistory.storedata` |
| Locations | `cache.sqlite`, app geodata, EXIF GPS on photos (`exiftool`) |
| Installed/used apps | `/data/data/<pkg>/`, `shared_prefs/*.xml`, iOS `Manifest.db` |
| Account creds / tokens | `shared_prefs`, Keychain (iOS), app DBs |

> iOS timestamps are seconds since **2001-01-01** (add 978307200 to reach Unix epoch). Pull `.db`, `.db-wal`, and `.db-shm` together — the WAL holds the newest unflushed rows.

### 4i. Correlate across artifacts (when you get more than one)

Incidents usually hand you a **set** — e.g. a pcap + a memory dump + event logs — that describe the same attack from different angles. Build one timeline so the answers line up and you can fill gaps (the pcap gives the C2 IP, memory gives the process that opened it, evtx gives the logon that started it).

```bash
# Normalize everything into a single Plaso timeline:
log2timeline.py case.plaso /mnt/disk          # disk/registry/evtx/browser all at once
log2timeline.py --parsers winevtx case.plaso ./evtx/
psort.py -o l2tcsv case.plaso -w master_timeline.csv
# Open master_timeline.csv in Timeline Explorer (or sort/grep) and read the story in order.
```

**Pivot points that stitch artifacts together:**

| You found (artifact A) | Pivot on | Confirm in (artifact B) |
| --- | --- | --- |
| C2 IP in `windows.netscan` | IP | pcap Conversations → what was sent |
| Suspicious PID + cmdline (memory) | process name / time | evtx 4688 / 4104 → how it launched |
| Logon from odd IP (evtx 4624) | source IP + time | pcap → the session; memory → resulting process |
| Dropped filename (disk `$MFT`) | filename / hash | memory `filescan`, pcap HTTP object, maldoc payload |
| Webshell hit (Linux access.log) | timestamp + URI | bash history / dropped files at that time |

Anchor on **time + one shared IOC** (an IP, a filename, a username) and walk it through every artifact you were given.

> ⚡ **For the fast way to actually build and slice these timelines — see [§7](#7-fast-timeline-building--correlation).** Don't run full Plaso on a whole disk mid-event; it can take hours.

---

## 5. Volatility Deep-Dive (memory analysis reference)

Tomorrow you'll be **given** the memory image — go straight to **4a** and this section for the deep plugin reference. Keep **Step 1** only for the rare challenge that hands you a live VM/host to acquire the RAM from yourself.

**Step 1 (only if you must acquire it yourself) — get a memory image off a system**
```bash
# Linux (LiME):
insmod lime.ko "path=/tmp/mem.lime format=lime"
# Linux fallback (no tools): cp /proc/kcore /tmp/mem.raw   (big/slow)
# Windows (winpmem/DumpIt):  winpmem.exe mem.raw
```

**Step 2 — identify**
```bash
vol -f mem.raw windows.info      # parses image + confirms OS build
```

**Step 3 — core triage (in order)**
```bash
vol -f mem.raw windows.pstree       # odd parent/child (winword.exe -> cmd.exe)
vol -f mem.raw windows.cmdline      # exact command lines
vol -f mem.raw windows.netscan      # active/past network connections
vol -f mem.raw windows.malfind      # process hollowing / injected shellcode
vol -f mem.raw windows.hashdump     # local account hashes, if SAM/SYSTEM resident
```

**Step 4 — pull artifacts referenced by what you found**
```bash
vol -f mem.raw windows.filescan | grep -i <keyword>
vol -f mem.raw windows.dumpfiles --virtaddr <addr> -o out/
vol -f mem.raw windows.memmap --pid <pid> --dump -o out/
```

**Step 5 — registry / console / extras**
```bash
vol -f mem.raw windows.registry.hivelist
vol -f mem.raw windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Run"
vol -f mem.raw windows.consoles      # full console scrollback incl. command output
vol -f mem.raw windows.clipboard
```

**Linux images:** `linux.pslist`, `linux.bash` (shell history from RAM), `linux.psaux`, `linux.malfind`, `linux.lsof` — needs a matching ISF symbol table for the exact kernel build (auto-fetched, else `dwarf2json`).

---

## 6. Answer-Format Discipline & Common Question Patterns

Correct findings get marked wrong on format. Before submitting, match the format **exactly**:

- **Timestamps:** copy the exact string, including timezone (UTC vs local). Watch for the log's own TZ.
- **Hashes:** lowercase, full length, right algorithm (MD5 vs SHA1 vs SHA256). `sha256sum`, don't eyeball.
- **IP/port:** as asked — `1.2.3.4` vs `1.2.3.4:443`.
- **File paths:** full path, correct slashes (`C:\Users\...` for Windows, `/var/...` for Linux).
- **MITRE ATT&CK:** technique ID format `T1059.001`, not the name.
- **Flags:** submit the literal string, often `nexsec26{...}` — don't trim or re-case.
- **Process names:** exact case and extension (`powershell.exe`).

**Recurring question types and the one tool that answers each:**

| "They ask..." | Go straight to |
| --- | --- |
| "When did the attack start?" | first 4624 Type 3/10, or earliest malicious log2timeline row |
| "What was the malicious process?" | `windows.pstree` / `windows.malfind` |
| "What command did they run?" | `windows.cmdline` / `windows.consoles` / 4104 / `.bash_history` |
| "What's the C2 address?" | `windows.netscan` / pcap Conversations |
| "What persistence did they set?" | Run keys, 7045 service, 4698 task, `authorized_keys`, cron |
| "What did they exfiltrate?" | pcap `--export-objects`, large outbound POST/STOR |
| "Did they cover tracks?" | event 1102, cleared `.bash_history`, timestomped `$MFT` |
| "What's in the macro/payload?" | `olevba` / `pdf-parser` → decode the base64/URL |
| "Hidden data in this image?" | `zsteg -a` / `steghide` / `binwalk -e` |

---

## 7. Fast Timeline Building & Correlation

Full `log2timeline` on a whole disk can take **hours** — too slow mid-event. Build only what the question needs, slice to the incident window, and correlate on one pivot. In order of speed:

### 7a. Filesystem timeline in seconds (Sleuth Kit `mactime`)
```bash
# raw image at partition offset $OFF (mmls to find it); .E01 -> ewfmount first
fls -r -m "C:/" -o $OFF disk.img > bodyfile              # Linux image: fls -r -m / -o $OFF
mactime -b bodyfile -d -z UTC > fs_timeline.csv           # full, CSV, sortable
mactime -b bodyfile -d -z UTC 2026-11-24..2026-11-26 > window.csv   # just the incident window
```
The single biggest speedup — pure file MACB times, no registry/log parsing. Pull `$MFT` detail later only if a question needs it (`analyzeMFT.py`).

### 7b. Event-log timeline in seconds (Hayabusa)
```bash
hayabusa csv-timeline -d ./evtx/ -o out/evtx_tl.csv -p verbose     # fast, with detections built in
```

### 7c. Full super-timeline, but faster (targeted Plaso + window slice)
Only when you genuinely need FS + registry + evtx + browser in one view:
```bash
# parse ONLY useful sources, not every parser (this is the big win):
log2timeline.py --parsers 'mft,usnjrnl,winevtx,winreg,prefetch,webhist,lnk,olecf' \
                case.plaso /mnt/disk
# slice to the window at OUTPUT time so it's fast to read:
psort.py -o l2tcsv case.plaso \
  "date > '2026-11-24 00:00:00' AND date < '2026-11-26 00:00:00'" -w window.csv
```
`--parsers` + a date filter turn a multi-hour run into minutes. `-o dynamic` gives a cleaner column set if you prefer.

### 7d. Correlate FAST — one pivot, one window, one grep
You rarely need a merged super-timeline to answer a single question. Faster:
1. **Find the pivot once** — the first bad logon / odd process / exploit request — and note its **UTC time** + one **IOC** (IP, filename, user).
2. **Grep every artifact** to a ±5-min window around it, or grep that one IOC across everything:
```bash
IOC='10.10.14.7'                 # or a filename / username
grep -rIn "$IOC" out/ /mnt/disk/var/log/ bodyfile out/evtx_tl.csv   # one IOC, every source
awk -F',' '$1>="2026-11-24 14:30" && $1<="2026-11-24 14:40"' window.csv   # the time window
```

### 7e. Merge different sources into ONE sortable stream
When you do need everything side by side, normalize each to `UTC<TAB>SOURCE<TAB>detail`, concat, sort:
```bash
# pcap
tshark -r cap.pcap -t ad -T fields -e frame.time_utc -e ip.src -e ip.dst -e _ws.col.Info \
  | awk -F'\t' '{print $1"\tPCAP\t"$2" -> "$3"  "$4}'          >> merged.tsv
# filesystem (bodyfile from 7a)
mactime -b bodyfile -d -z UTC | awk -F',' 'NR>1{print $1"\tFS\t"$8}'   >> merged.tsv
# evtx (hayabusa csv: first col is the timestamp)
awk -F',' 'NR>1{print $1"\tEVTX\t"$0}' out/evtx_tl.csv           >> merged.tsv
sort merged.tsv | less            # the whole incident, one stream, in order
```

### 7f. Visual correlation (if available)
- **Timesketch** — import a `.plaso` file, then tag/search/share a timeline across all sources (best for big multi-artifact cases).
- **Timeline Explorer** (Windows) / LibreOffice Calc / `csvkit` `csvgrep` — filter the CSV by time or keyword.

> **Time zones are the #1 correlation bug.** Force everything to **UTC** (`-z UTC`, `tshark -t ad`, Plaso defaults to UTC) before comparing — a pcap in local time next to evtx in UTC makes events look hours apart and the story won't line up.

---

## 8. Unstuck — when any phase stalls

Don't burn 30 minutes on one wall. Find your phase, try the move; if it still won't give → **skip, bank the answers you have, come back.** Points are per-question.

| Stuck at… | The move |
| --- | --- |
| **`file` says `data`, can't ID it** | `binwalk <f>` + `xxd <f> \| head` (magic bytes); try it as each type: `mmls` (disk), `vol -f <f> windows.info` (memory), `7z l` (archive); high entropy all through → encrypted/compressed, hunt the password/key in other artifacts |
| **Container won't mount ([4.1](#41-containers-forensic-images--vm-files--get-to-a-mountable-form-first))** | switch method: `qemu-nbd` ↔ `guestmount` ↔ `ewfmount`/`affuse`; `qemu-img info` for format + backing file; filesystem corrupt → `testdisk` to rebuild the partition table, or `photorec`/`tsk_recover` to carve files out |
| **`vol windows.info` fails** | wrong layer/tool: is it a **hiberfil** (`hibr2bin`) or a **disk**, not RAM? try **Volatility 2** + a profile for old dumps; last resort `strings -el mem.raw \| grep` + `bulk_extractor` |
| **Linux memory, no symbols** | build an ISF: `dwarf2json linux --elf vmlinux > kernel.json` → drop in `volatility3/symbols/linux/`; can't? fall back to `strings`/`bulk_extractor`/`photorec` and grep for bash history, configs, keys |
| **pcap: nothing obvious / all TLS** | no keys → pivot to metadata: TLS **SNI**, cert **CN**, **JA3**, **DNS** names, packet **size/timing** (beacon); check non-HTTP protocols; `zeek -r f.pcap` then read `conn.log`/`dns.log`/`ssl.log`; NetworkMiner for auto-carved creds/files |
| **evtx: logs cleared / missing** | the **1102 clear** is often itself the answer; pivot to **Sysmon/Operational**, **PowerShell/Operational (4104)**, `$MFT`/prefetch for execution, or the pcap — one source covering tracks rarely covers all |
| **Encoded blob won't decode** | CyberChef **Magic** (tick *Intensive mode*); `xortool` if it's XOR; `file` it after each decode (it may become a real file → `binwalk`); classical cipher → **dcode.fr** / quipqiup |
| **Stego: found nothing** | wrong layer — run **all**: `zsteg -a`, `steghide extract` (password = challenge title/words), `stegseek rockyou`, `exiftool`, `binwalk -e`, declared-vs-real dimensions, each plane in Stegsolve; audio → **spectrogram**; or **aperisolve.com** (runs them all at once) |
| **Artifact is password-protected** | crack it: `zip2john`/`office2john`/`pdf2john <f> > h && john --wordlist=rockyou.txt h`; BitLocker → `bitlocker2john`; the password is often in the challenge text or another artifact |
| **Timelines won't line up** | **normalize every source to UTC** (the usual culprit); pivot on a *different* shared IOC; widen the window to ±15 min; check the brief for noted clock skew |
| **Answer rejected but you're sure** | it's the **format** ([§6](#6-answer-format-discipline--common-question-patterns)): wrong timezone, hash algorithm, case, path slashes, a trailing space/newline, or they want `CVE-…` / `T####` / defanged `hxxp` — try the other representation |
| **Totally blank on a question** | re-read it — the wording usually names the artifact/tool; run the universal sweep below; then skip and return |

**Universal last resorts (run these on literally anything):**
```bash
strings -n 6 <artifact> | grep -iE 'flag|nexsec26\{|password|http|BEGIN'   # cheap wins first
binwalk -e <artifact>                 # embedded files
bulk_extractor -o be_out <artifact>   # carves emails, URLs, IPs, card numbers, keys
exiftool -a -G1 <artifact>            # metadata you skipped
# then: CyberChef Magic on any blob · aperisolve on any image · searchsploit/trickest on any version
```

---

## 9. Checking Which CVE Produced the Evidence

When a question asks "which vulnerability / CVE was used," you work **backwards from the evidence.** Five steps:

**1. Pull the service + version that got hit** — from the evidence, not from memory:
```bash
# web logs / pcap: the server banner or Server: header tells you the exact product + version
grep -aoiE 'Server: [^\r]+' evidence/access.log | sort -u
tshark -r evidence/cap.pcap -Y 'http.response' -T fields -e http.server | sort -u
# memory/disk: the running service binary and its version (e.g. from cmdline / file version)
```

**2. Grab the attack payload or URI** and match it to a known signature → [05 §4 payload signatures](05-cve-poc-forensics.md#4-payload-signatures-youll-literally-see-in-the-evidence). E.g. `${jndi:` = Log4Shell, `() { :;};` = Shellshock, `human2.aspx` = MOVEit.
```bash
grep -aoiE '\$\{jndi:|\(\) \{ :;\};|/cgi-bin/|\.\./|rO0AB|__VIEWSTATE' evidence/access.log
```

**3. Look it up** (works offline after you cloned the CVE repos in [05 §1](05-cve-poc-forensics.md#1-instant-poc-lookup-for-any-cve-clone-these-tonight)):
```bash
searchsploit apache 2.4.49          # by product + version
searchsploit --cve 2021-41773       # if you already suspect a CVE id
grep -rl "2.4.49" ~/cve/trickest/   # browse the local trickest clone
```

**4. Confirm by correlating** (see [§4i](#4i-correlate-across-artifacts-when-you-get-more-than-one) / [§7](#7-fast-timeline-building--correlation)): the exploited service → the process it spawned → the outbound connection, all at the **same timestamp**. If they line up, that's your CVE.

**5. Answer** as `CVE-YYYY-NNNNN` (and the MITRE `T####` if asked) — format per [§6](#6-answer-format-discipline--common-question-patterns).

> The full CVE → forensic-indicator → PoC map lives in **[05-cve-poc-forensics.md](05-cve-poc-forensics.md)** — keep it open alongside this tab.

> **Workflow:** read the full question list first, pick the one artifact + tool each question needs, and answer only what's asked. Don't try to fully reverse the whole image — points are per-question.
