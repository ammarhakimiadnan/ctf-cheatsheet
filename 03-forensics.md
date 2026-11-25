# Forensics Cheatsheet

DFIR for a CTF: you are usually **handed artifacts** (a memory dump, a disk image, a pcap, event logs, a suspicious document) and a **question list**, and scored on exact answers. This tab is built to get you from "here are the files" to "here is the answer" fast.

Read it in this order on game day:
1. **Section 0** — install everything tonight so nothing blocks you tomorrow.
2. **Section 1** — triage any artifact in the first 5 minutes.
3. **Section 4** — the full per-incident-type walkthroughs (the meat).
4. **Section 6** — answer-format discipline so correct answers aren't marked wrong.

---

## 0. Toolkit Setup (do this the night before)

Pwnbox / Parrot / Ubuntu / Kali all work. Run the one-shot block, then the extras you expect to need. If egress is blocked tomorrow, everything here must already be installed — **don't leave installs for game day.**

### 0a. One-shot apt base

```bash
sudo apt update && sudo apt install -y \
  python3-pip pipx git curl wget unzip p7zip-full \
  sleuthkit autopsy ewf-tools libewf-dev \
  wireshark tshark tcpdump \
  binwalk foremost bulk-extractor scalpel \
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
# (fallback install if pipx misbehaves)
# pip3 install volatility3 --break-system-packages

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
# Run on Linux with:  dotnet MFTECmd.dll -f '$MFT' --csv out/
# Easiest: run EZ tools + Timeline Explorer on a Windows analysis VM if you have one.

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
```

### 0h. Wordlists + final sanity check

```bash
# rockyou
sudo gzip -dk /usr/share/wordlists/rockyou.txt.gz 2>/dev/null
ls -la /usr/share/wordlists/rockyou.txt

# verify the heavy hitters resolve
for t in vol tshark mmls fls binwalk exiftool olevba steghide zsteg log2timeline.py; do
  printf '%-18s ' "$t"; command -v "$t" || echo "MISSING — install before game day"
done
```

> Keep all cloned tools under `~/tools/` and add release-binary dirs to `PATH` in `~/.bashrc`, same as the boot2root tab. One folder, no hunting mid-challenge.

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

## 2. Live-Box & Standalone File Forensics

(Artifacts you find on a boot2root box, or small given files: images, archives, encoded blobs.)

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
| Programs executed (even if deleted) | **Prefetch**: `PECmd.exe -d /mnt/disk/Windows/Prefetch --csv out/` • **ShimCache**: `AppCompatCacheParser` on `SYSTEM` • **Amcache**: `AmcacheParser -f /mnt/disk/Windows/AppCompat/Programs/Amcache.hve --csv out/` |
| Persistence | RegRipper `SOFTWARE` (Run/RunOnce), Scheduled Tasks `\Windows\System32\Tasks`, Services, Startup folder |
| User accounts / new admin | RegRipper `SAM` → users & groups; correlate with event log 4720 |
| USB devices plugged in | `rip.pl -r SYSTEM -p usbstor` + `SOFTWARE` → USB serials & first/last connect |
| Recently opened files | `NTUSER.DAT` → RecentDocs, `rip.pl -r NTUSER.DAT -p recentdocs` |
| What user typed in Run / Explorer | `NTUSER.DAT` → RunMRU, TypedPaths |
| Deleted files | `tsk_recover`, or Recycle Bin: `RBCmd -d '/mnt/disk/$Recycle.Bin' --csv out/` |
| Browser history / downloads | `hindsight -i /mnt/disk/Users/<u>/AppData/Local/Google/Chrome/User\ Data/Default -o out/browser` |
| $MFT timeline / file creation times | `MFTECmd.exe -f '/mnt/disk/$MFT' --csv out/` → look for timestomping (0-ns `$STD_INFO` vs `$FILE_NAME` mismatch) |
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
mkdir -p out && networkminer capture.pcap        # GUI: files, images, creds, hosts tabs
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

---

## 5. Volatility Deep-Dive (dumping + analyzing live memory)

Use this when you're on a **live boot2root box** and stuck on creds/persistence — dumping RAM is a heavier side-path, not the default route to root.

**Step 1 — get a memory image off the box**
```bash
# Linux (LiME):
insmod lime.ko "path=/tmp/mem.lime format=lime"
# Linux fallback (no tools): cp /proc/kcore /tmp/mem.raw   (big/slow)
# Windows (winpmem/DumpIt uploaded):  winpmem.exe mem.raw
```
Transfer it back with the file-transfer steps in the Tools & Setup tab.

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

> **Workflow:** read the full question list first, pick the one artifact + tool each question needs, and answer only what's asked. Don't try to fully reverse the whole image — points are per-question.
