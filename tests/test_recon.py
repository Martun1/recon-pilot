import asyncio, sys, unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import recon_pilot as rp


def fp(port, banner):
    s = rp.Service(port, banner=banner)
    rp.fingerprint(s)
    return s


class TestFingerprint(unittest.TestCase):
    def test_vsftpd_backdoor(self):
        s = fp(21, "220 (vsFTPd 2.3.4)")
        self.assertEqual((s.name, s.product, s.version), ("ftp", "vsFTPd", "2.3.4"))
        self.assertTrue(any("CVE-2011-2523" == a.get("ref") for a in s.alerts))

    def test_smtp_not_ftp(self):
        s = fp(25, "220 mail ESMTP Exim 4.89 Ubuntu")
        self.assertEqual((s.name, s.product), ("smtp", "Exim"))

    def test_openssh_enum(self):
        self.assertTrue(fp(22, "SSH-2.0-OpenSSH_7.2p2 Ubuntu").alerts)
        self.assertFalse([a for a in fp(22, "SSH-2.0-OpenSSH_9.6p1").alerts if a.get("ref")])

    def test_http(self):
        s = fp(80, "HTTP/1.1 200 OK\r\nServer: Apache/2.4.49 (Unix)\r\n")
        self.assertEqual((s.product, s.version), ("Apache", "2.4.49"))

    def test_ports(self):
        self.assertEqual(rp.parse_ports("22,80,100-102"), [22, 80, 100, 101, 102])
        with self.assertRaises(ValueError):
            rp.parse_ports("0-5")


class TestLiveScan(unittest.TestCase):
    def test_scan_local_listener(self):
        async def run():
            srv = await asyncio.start_server(lambda r, w: (w.write(b"SSH-2.0-OpenSSH_8.9\r\n"), w.close()), "127.0.0.1", 0)
            port = srv.sockets[0].getsockname()[1]
            res = await rp.scan("127.0.0.1", [port, port + 1 if port < 65535 else port - 1], 10, 0.5, False)
            srv.close()
            return port, res
        port, res = asyncio.run(run())
        self.assertEqual([s.port for s in res], [port])
        self.assertEqual(res[0].name, "ssh")


if __name__ == "__main__":
    unittest.main()
