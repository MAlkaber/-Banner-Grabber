#!/usr/bin/env python3
"""
Banner Grabber
================
Connects to open TCP ports and reads whatever the service announces
about itself - the "banner" - to help identify what's actually running,
not just that the port is open.

Project 04 of a pentest/red-team learning portfolio.
Read README.md first for the concept walkthrough.

Usage:
    python3 banner_grabber.py <host> <ports> [--timeout SECONDS]

Examples:
    python3 banner_grabber.py scanme.nmap.org 22
    python3 banner_grabber.py scanme.nmap.org 22,80,443
"""

import argparse
import socket
import ssl

# A handful of protocols don't say anything until you speak first. For
# those (HTTP/HTTPS on common ports), we send a minimal, protocol-correct
# probe. Everything else is simply read from cold - many services (SSH,
# FTP, SMTP, plenty of custom TCP services) announce themselves the
# instant a client connects, with no request required at all.
HTTP_PROBE = b"HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n"
HTTP_PORTS = {80, 443, 8080, 8000}


def grab_banner(host: str, port: int, timeout: float) -> str:
    """
    Connect to host:port, optionally send a protocol probe, and read back
    whatever bytes the service sends within the timeout window. Returns a
    cleaned-up string, or a bracketed status like "[closed]" if nothing
    useful came back.
    """
    use_tls = port == 443

    try:
        raw_sock = socket.create_connection((host, port), timeout=timeout)
    except (ConnectionRefusedError, socket.timeout, OSError):
        return "[closed / unreachable]"

    sock = raw_sock
    if use_tls:
        # HTTPS servers won't speak plaintext HTTP - a TLS handshake has
        # to happen first. check_hostname=False + verify_mode=CERT_NONE
        # skips certificate trust validation, which is fine here because
        # we're only reading a banner, not trusting this connection with
        # anything sensitive - never disable verification like this for
        # a connection that actually needs to be trusted.
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            sock = ctx.wrap_socket(raw_sock, server_hostname=host)
        except ssl.SSLError as exc:
            raw_sock.close()
            return f"[TLS handshake failed: {exc}]"

    try:
        if port in HTTP_PORTS:
            sock.sendall(HTTP_PROBE % host.encode())
        # For everything else, we just try to read. If the service
        # doesn't banner on connect and doesn't understand a blind read,
        # this simply times out - which is itself a useful result: it
        # tells you the service is "probe-shy", not that nothing is there.
        data = sock.recv(4096)
    except socket.timeout:
        sock.close()
        return "[no response within timeout]"
    finally:
        sock.close()

    if not data:
        return "[connection closed with no data]"

    # Decode leniently - banners can contain non-UTF8 bytes - and only
    # keep the first few lines, since HTTP responses can run long.
    text = data.decode("utf-8", errors="replace")
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return " | ".join(lines[:3]) if lines else "[empty response]"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Grab service banners from one or more open TCP ports."
    )
    parser.add_argument("host", help="Target hostname or IP address")
    parser.add_argument("ports", help="Port or comma-separated list, e.g. '22,80,443'")
    parser.add_argument(
        "--timeout", type=float, default=3.0,
        help="Seconds to wait for a banner (default: 3.0)",
    )
    args = parser.parse_args()

    ports = [int(p.strip()) for p in args.ports.split(",") if p.strip()]

    print(f"Target: {args.host}\n")
    for port in ports:
        banner = grab_banner(args.host, port, args.timeout)
        print(f"  {port:>5}/tcp  {banner}")


if __name__ == "__main__":
    main()
