#!/usr/bin/env python3
"""
Practice lab: fake services with realistic (vulnerable-looking) banners on 127.0.0.1.

Nothing here is actually vulnerable. Each listener only sends a banner/response
and closes, so you can safely practise recon-pilot (or nmap -sV) on your own machine.

    python3 lab/practice_lab.py          # Ctrl+C to stop
    python3 recon_pilot.py 127.0.0.1 -p 1-10000
"""
import asyncio

SERVICES = {
    2121: ("FTP", b"220 (vsFTPd 2.3.4)\r\n", None),
    2222: ("SSH", b"SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.8\r\n", None),
    2525: ("SMTP", b"220 mail.lab.local ESMTP Exim 4.89 Ubuntu\r\n", None),
    3306: ("MySQL", b"J\x00\x00\x00\n5.7.33-0ubuntu0.16.04.1\x00\x08\x00\x00\x00abcdefgh\x00\xff\xf7\x08\x02\x00"
                    b"\xff\x81\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00ijklmnopqrst\x00mysql_native_password\x00", None),
    5900: ("VNC", b"RFB 003.008\n", None),
    6379: ("Redis", None, b"$120\r\n# Server\r\nredis_version:4.0.9\r\nredis_mode:standalone\r\nos:Linux 4.15.0 x86_64\r\n"),
    8080: ("HTTP", None, b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.49 (Unix)\r\nX-Powered-By: PHP/5.6.40\r\n"
                         b"Content-Type: text/html\r\nContent-Length: 0\r\n\r\n"),
    8443: ("HTTP", None, b"HTTP/1.1 302 Found\r\nServer: nginx/1.24.0\r\nLocation: /login\r\n\r\n"),
}


def handler(banner, response):
    async def handle(reader, writer):
        try:
            if banner:
                writer.write(banner)
            else:
                await asyncio.wait_for(reader.read(1024), 3)
                writer.write(response)
            await writer.drain()
        except (asyncio.TimeoutError, ConnectionError):
            pass
        finally:
            writer.close()
    return handle


async def main():
    servers = []
    for port, (name, banner, resp) in SERVICES.items():
        try:
            servers.append(await asyncio.start_server(handler(banner, resp), "127.0.0.1", port))
            print(f"  [lab] {name:<6} listening on 127.0.0.1:{port}")
        except OSError as e:
            print(f"  [lab] {name:<6} port {port} unavailable ({e.strerror})")
    print("  [lab] ready. Scan with: python3 recon_pilot.py 127.0.0.1 -p 1-10000   (Ctrl+C to stop)")
    await asyncio.gather(*(s.serve_forever() for s in servers))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n  [lab] stopped")
