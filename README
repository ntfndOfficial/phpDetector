<div align="center">

```
  ____  _           ____       _            _             
 |  _ \| |__  _ __ |  _ \  ___| |_ ___  ___| |_ ___  _ __ 
 | |_) | '_ \| '_ \| | | |/ _ \ __/ _ \/ __| __/ _ \| '__|
 |  __/| | | | |_) | |_| |  __/ ||  __/ (__| || (_) | |   
 |_|   |_| |_| .__/|____/ \___|\__\___|\___|\__\___/|_|   
              |_|                                           
```

**PHP Technology Detection Scanner**

![Bash](https://img.shields.io/badge/Shell-Bash-4EAA25?style=flat-square&logo=gnu-bash&logoColor=white)
![Version](https://img.shields.io/badge/Version-1.1.0-red?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-lightgrey?style=flat-square)

*Detect PHP-powered targets via HTTP headers and response body — single URL or bulk list, with parallel scanning and version extraction.*

</div>

---

## Overview

`phpDetector` identifies PHP presence on web targets by analyzing HTTP response headers and body content. It extracts PHP version strings when exposed, supports authenticated scanning via cookie jars, and handles bulk target lists with parallel execution.

Primary use cases:
- **Recon / attack surface mapping** — identify PHP targets in scope before php2shell or file upload testing
- **Version fingerprinting** — surface unpatched PHP installs exposing `X-Powered-By` headers
- **Bulk scanning** — pipe output of subdomain enumeration tools directly into phpDetector

---

## Features

| Feature | Detail |
|---|---|
| **Dual detection levels** | Level 1 (precise) or Level 2 (broad) grep patterns |
| **Version extraction** | Parses `X-Powered-By: PHP/x.x.x` from response headers |
| **Bulk / file mode** | One URL per line, parallel execution via `xargs -P` |
| **Cookie jar support** | Netscape-format cookie files for auth-gated pages |
| **Output file** | ANSI-free `[PHP DETECTED]` hits written to file |
| **Filter modes** | `--only-php` and `--version-only` for targeted output |
| **SSL bypass** | `-k` flag on all requests — no cert errors |
| **Redirect follow** | Follows up to 5 redirects per request |

---

## Requirements

- `bash` 4.0+
- `curl`
- `grep`
- `xargs`

All standard on Kali / Parrot / Ubuntu. macOS users may need GNU `grep` (`brew install grep`).

---

## Installation

```bash
git clone https://github.com/youruser/phpDetector.git
cd phpDetector
chmod +x phpDetector
sudo mv phpDetector /usr/local/bin/
```

Verify:

```bash
phpDetector -h
```

---

## Usage

```
phpDetector -u <url|file> [OPTIONS]
```

### Options

| Flag | Description |
|---|---|
| `-u <target>` | Single URL **or** path to file containing URLs (one per line) |
| `--level 1` | Precise detection: `PHPSESSID`, `.php` extensions *(default)* |
| `--level 2` | Broad detection: any `php` occurrence in headers/body |
| `-t <threads>` | Parallel threads for file mode *(default: 10)* |
| `--timeout <sec>` | Per-request timeout in seconds *(default: 10)* |
| `--output <file>` | Write `[PHP DETECTED]` hits to file, plain text, no ANSI |
| `--only-php` | Suppress `[NOT PHP]` and `[SKIP]` lines from stdout |
| `--version-only` | Show only targets where PHP version was extracted from headers |
| `--cookie <cookiejar>` | Cookie jar file for authenticated requests (Netscape format) |
| `--no-color` | Disable ANSI color output |
| `-h, --help` | Show help menu |

---

## Detection Levels

### Level 1 — Precise *(default)*

```
grep -Eio 'PHPSESSID|\.php([/?#"]|$)'
```

Matches:
- `Set-Cookie: PHPSESSID=...` in response headers
- `.php`, `.php?id=1`, `.php"`, `.php/` in response body

**Low false-positive rate.** May miss PHP installations that strip headers and serve generic extensions (e.g. `.html` rewrites via `.htaccess`).

### Level 2 — Broad

```
grep -Ein 'php'
```

Matches any occurrence of `php` (case-insensitive) in headers or body.

**High coverage, expect noise.** Useful when Level 1 returns nothing but the target is suspected to be PHP (e.g. WordPress with aggressive hardening, custom frameworks).

---

## Examples

### Single URL

```bash
phpDetector -u https://target.com
phpDetector -u https://target.com --level 2
```

**Expected output — PHP detected:**

```
[*] Mode         : Single URL
[*] Target       : https://target.com
[*] Level        : 1
[*] Timeout      : 10s

[PHP DETECTED] https://target.com [Version: 8.1.27]
   ↳ /tmp/headers.txt:PHPSESSID
   ↳ /tmp/body.html:.php?
   ↳ /tmp/body.html:.php"

[done]
```

**Expected output — no PHP:**

```
[NOT PHP   ] https://target.com

[done]
```

---

### Bulk Scan from File

`targets.txt`:
```
https://shop.target.com
https://admin.target.com
https://portal.target.com
# internal staging
https://staging.target.com
```

```bash
phpDetector -u targets.txt --level 1 -t 20 --timeout 8
```

**Expected output:**

```
[*] Mode         : File scan
[*] Target       : targets.txt (4 URLs)
[*] Level        : 1
[*] Threads      : 20
[*] Timeout      : 8s

[PHP DETECTED] https://shop.target.com [Version: 7.4.3]
   ↳ PHPSESSID
   ↳ .php"
[NOT PHP   ] https://admin.target.com
[PHP DETECTED] https://portal.target.com
   ↳ .php?
[SKIP] https://staging.target.com (curl err: 6)

[done]
```

---

### Save Hits to File

```bash
phpDetector -u targets.txt --only-php --output hits.txt
```

`hits.txt` (no ANSI, ready for piping or reporting):
```
[PHP DETECTED] https://shop.target.com [Version: 7.4.3]
[PHP DETECTED] https://portal.target.com
```

Summary line at exit:
```
[+] 2 PHP hit(s) saved → hits.txt
```

---

### Version-Only Mode

Filter to targets that actively leak their PHP version in headers — these are the highest-priority targets:

```bash
phpDetector -u targets.txt --version-only --output exposed_versions.txt
```

**Expected output:**

```
[PHP DETECTED] https://legacy.target.com [Version: 5.6.40]
   ↳ PHPSESSID
[PHP DETECTED] https://shop.target.com [Version: 7.4.3]
   ↳ .php?

[+] 2 PHP hit(s) saved → exposed_versions.txt
```

---

### Authenticated Scanning with Cookie Jar

For targets behind login walls — generate a cookie jar first, then pass it to phpDetector:

**Step 1 — Capture session cookie with curl:**

```bash
curl -sk \
  -c session.jar \
  -b session.jar \
  -X POST \
  -d 'username=admin&password=admin123' \
  https://target.com/login.php
```

**Step 2 — Scan with active session:**

```bash
phpDetector -u targets.txt --cookie session.jar --output hits.txt
```

**Burp Suite alternative:**

1. Intercept a logged-in request
2. Right-click → *Copy as curl command*
3. Add `-c session.jar` to capture cookies
4. Use resulting `session.jar` with `--cookie`

Cookie jars are passed with `-b` (send) and `-c` (update) on every request, keeping session tokens alive across the scan.

---

### Full Combined Example

```bash
phpDetector -u scope.txt \
  --level 2 \
  --only-php \
  --version-only \
  --cookie burp_session.jar \
  --output exposed_php_versions.txt \
  -t 30 \
  --timeout 8 \
  --no-color | tee live_scan.log
```

---

## Workflow Integration

### With `subfinder` / `httpx`

```bash
subfinder -d target.com -silent \
  | httpx -silent \
  | tee subdomains_live.txt

phpDetector -u subdomains_live.txt --level 1 --only-php --output php_targets.txt
```

### With `waybackurls`

```bash
waybackurls target.com \
  | grep -Eo 'https?://[^/]+' \
  | sort -u > roots.txt

phpDetector -u roots.txt --level 1 --only-php --output php_targets.txt
```

### Filter versioned targets for CVE research

```bash
phpDetector -u targets.txt --version-only --no-color --output versions.txt

# Find PHP < 8.0 targets
grep -E 'Version: [5-7]\.' versions.txt
```

---

## Technical Internals

### curl Flags Used

| Flag | Purpose |
|---|---|
| `-sSL` | Silent, follow redirects |
| `-k` | Skip SSL certificate verification |
| `-D <file>` | Dump response headers to file |
| `-o <file>` | Write response body to file |
| `--max-redirs 5` | Follow up to 5 redirects |
| `--connect-timeout 5` | TCP handshake timeout |
| `--max-time <N>` | Total request timeout |
| `-b / -c <jar>` | Send / update cookie jar |

Headers and body are saved to separate temp files per request (`mktemp -d`) and cleaned up after each scan. This avoids cross-contamination in parallel mode.

### Version Extraction

```
grep -Eio 'PHP/[0-9]+\.[0-9]+(\.[0-9]+)?' headers.txt
```

Captures version strings from:
```
X-Powered-By: PHP/8.1.27
X-Generator: PHP/7.4.3
```

### Parallel Execution

File mode uses `xargs -P <threads>` to run `scan_url` concurrently. All variables and functions are exported to subshells via `export -f`. File writes use `>>` (O_APPEND), which is atomic for single-line writes on Linux — no lock file needed.

---

## Output Reference

| Line | Meaning |
|---|---|
| `[PHP DETECTED] <url> [Version: x.x.x]` | PHP found, version leaked in headers |
| `[PHP DETECTED] <url>` | PHP found, no version in headers |
| `[NOT PHP   ] <url>` | No PHP indicators found |
| `[SKIP] <url> (curl err: N)` | Request failed (timeout, DNS, refused) |

`[SKIP]` and `[NOT PHP]` are suppressed with `--only-php`.  
`[PHP DETECTED]` without version is suppressed with `--version-only`.  
`--output` captures only `[PHP DETECTED]` lines, always ANSI-free.

---

## License

MIT — use freely in authorized engagements.

---

<div align="center">
<sub>Built for authorized red team and penetration testing engagements only.</sub>
</div>
