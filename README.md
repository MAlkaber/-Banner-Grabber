# Banner Grabber

**Project 04** of a pentest/red-team learning portfolio — see the [full roadmap](../ROADMAP.md).

Connects to open TCP ports and reads what the service says about itself,
turning "port 22 is open" into "port 22 is running
`SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13`" — a specific, searchable
version string. This is the step between "the port is open" (Projects
01/03) and "is this thing vulnerable" (a later CVE-lookup project).

> ⚠️ Only run this against hosts you own or are authorized to test.
> Also know the limitation: banners are **self-reported by the target**
> and can be spoofed or stripped by a defender specifically to mislead
> tools like this one. Never treat a banner as proof — verify with a
> second method before relying on it in a real assessment.

## What it does

```
$ python3 banner_grabber.py scanme.nmap.org 22,80
Target: scanme.nmap.org

     22/tcp  SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
     80/tcp  HTTP/1.1 200 OK | Date: ... | Server: Apache/2.4.7 (Ubuntu)
```

## Concepts you need before reading the code

**Not every service "banners" the same way.** Some protocols announce
themselves the instant you connect, before you send anything — SSH, FTP,
and SMTP all do this, because their protocol spec says the server speaks
first. HTTP is the opposite: the server says nothing until it receives a
request line. That's why this tool sends a probe (`HEAD / HTTP/1.0`) only
for HTTP-ish ports, and just listens for everything else. Getting this
distinction wrong is a common beginner bug — a script that always sends
an HTTP probe will get garbage or nothing back from an SSH or FTP server,
which doesn't understand HTTP.

**Active vs. passive banner grabbing.** What this script does is
"active" — it makes a real connection to the target, which the target
can log and which an IDS can flag. "Passive" banner grabbing instead
reads banners other people already collected (e.g. from Shodan's
database) without ever touching the target yourself — quieter, but only
as fresh as whenever that data was last collected. We'll build a passive
version in the OSINT phase (Project 16).

**TLS is a wrapper around a plaintext connection.** Port 443 doesn't
speak HTTP directly — it speaks HTTP *inside* a TLS-encrypted tunnel.
`ssl.SSLContext.wrap_socket()` takes an already-connected plain TCP
socket and performs the TLS handshake on top of it, after which you can
send/receive plaintext HTTP exactly like you would on port 80 — the
encryption is transparent to your code from that point on. This script
deliberately disables certificate verification
(`verify_mode = ssl.CERT_NONE`) because it only wants to read a banner,
not establish a trusted connection — that's a reasonable choice *here*,
but disabling cert verification in anything that handles real data or
credentials is a serious vulnerability (it opens the door to
man-in-the-middle attacks) — never carry this pattern into other tools
without thinking about it first.

## Code walkthrough

Open [`banner_grabber.py`](banner_grabber.py) alongside this section.

- **`grab_banner()`** — the whole tool. Connects, wraps in TLS if the
  port is 443, sends an HTTP probe if the port looks HTTP-ish, then does
  one `recv(4096)` and returns whatever came back (or a bracketed status
  string explaining why nothing did).
- Notice the layered `try/except`: connection failures, TLS handshake
  failures, and read timeouts are all handled as *distinct, informative*
  outcomes instead of one generic "error" — that distinction matters a
  lot in a real assessment (closed vs. filtered vs. "open but the
  service is unusually quiet" are three different findings).

## Try it yourself (exercises)

1. Run this against a handful of ports on `scanme.nmap.org` (try `9929`
   and `31337` too — nmap's project intentionally runs oddities on those).
   What does an unrecognized service without an HTTP probe give you back?
2. Right now HTTPS on non-standard ports (e.g. `8443`) won't get TLS-wrapped
   because `use_tls` only checks `port == 443`. Fix this — how would you
   detect "this port probably needs TLS" more generally? (Hint: you could
   try plaintext first and fall back to TLS on failure.)
3. FTP servers usually banner immediately with something like
   `220 (vsFTPd 3.0.3)`. Find a public test FTP server (or spin one up in
   a lab VM) and confirm this script picks it up correctly with zero
   changes — that's the payoff of the "just read, don't assume a probe is
   needed" design.
4. (Preview of Project 22) Once you have a banner like
   `Apache/2.4.7 (Ubuntu)`, the natural next step is checking whether
   *that specific version* has known CVEs. Sketch how you'd extract just
   the version number from a banner string with a regex.

## Running it

```bash
git clone <your-repo-url>
cd 04-banner-grabber
python3 banner_grabber.py scanme.nmap.org 22,80
```

Standard library only — no `pip install` needed.

## What's next

**Project 05 — Wordlist Generator:** shifting from network recon to
password attacks — building custom, targeted wordlists (mutations,
leetspeak, name/date combos) instead of relying only on generic lists
like rockyou.txt.
