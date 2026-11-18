"""Socket-level tests for the loopback port scanner."""

import socket
import threading
import unittest
import unittest

import portscanner


class PortScannerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.stop_servers = threading.Event()

        cls.tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cls.tcp_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        cls.tcp_server.bind((portscanner.LOOPBACK, 0))
        cls.tcp_server.listen()
        cls.tcp_server.settimeout(0.1)
        cls.tcp_port = cls.tcp_server.getsockname()[1]

        cls.udp_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        cls.udp_server.bind((portscanner.LOOPBACK, 0))
        cls.udp_server.settimeout(0.1)
        cls.udp_port = cls.udp_server.getsockname()[1]

        cls.tcp_thread = threading.Thread(target=cls._accept_tcp, daemon=True)
        cls.udp_thread = threading.Thread(target=cls._echo_udp, daemon=True)
        cls.tcp_thread.start()
        cls.udp_thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.stop_servers.set()
        cls.tcp_server.close()
        cls.udp_server.close()
        cls.tcp_thread.join(timeout=1)
        cls.udp_thread.join(timeout=1)

    @classmethod
    def _accept_tcp(cls) -> None:
        while not cls.stop_servers.is_set():
            try:
                connection, _ = cls.tcp_server.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            connection.close()

    @classmethod
    def _echo_udp(cls) -> None:
        while not cls.stop_servers.is_set():
            try:
                data, address = cls.udp_server.recvfrom(1024)
                cls.udp_server.sendto(data, address)
            except socket.timeout:
                continue
            except OSError:
                return

    @staticmethod
    def unused_port(protocol: int) -> int:
        with socket.socket(socket.AF_INET, protocol) as sock:
            sock.bind((portscanner.LOOPBACK, 0))
            return sock.getsockname()[1]

    def test_tcp_open_port(self) -> None:
        self.assertEqual(portscanner.scan_tcp(self.tcp_port, 0.5), "open")

    def test_tcp_closed_port(self) -> None:
        port = self.unused_port(socket.SOCK_STREAM)
        self.assertEqual(portscanner.scan_tcp(port, 3.0), "closed")

    def test_udp_echo_port(self) -> None:
        self.assertEqual(portscanner.scan_udp(self.udp_port, 0.5), "open")

    def test_udp_closed_port(self) -> None:
        port = self.unused_port(socket.SOCK_DGRAM)
        self.assertEqual(portscanner.scan_udp(port, 0.5), "closed")


if __name__ == "__main__":
    unittest.main()