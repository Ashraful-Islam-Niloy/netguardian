"""Tests for NetGuardian's scanner helpers. Run with:

    python -m unittest discover -s tests -t .
"""
import unittest
from unittest import mock

from netguardian.core import scanner

WINDOWS_ARP = """
Interface: 192.168.1.5 --- 0xb
  Internet Address      Physical Address      Type
  192.168.1.1           aa-bb-cc-00-00-01     dynamic
  192.168.1.20          AA-BB-CC-00-00-02     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
  239.255.255.250       01-00-5e-7f-ff-fa     static
  255.255.255.255       ff-ff-ff-ff-ff-ff     static

Interface: 172.20.0.1 --- 0x1a
  Internet Address      Physical Address      Type
  172.20.0.2            00-15-5d-aa-bb-cc     dynamic
  224.0.0.22            01-00-5e-00-00-16     static

Interface: 192.168.1.5 --- 0xc
  Internet Address      Physical Address      Type
  192.168.1.1           aa-bb-cc-00-00-01     dynamic
"""

LINUX_ARP = """? (192.168.1.1) at aa:bb:cc:00:00:01 [ether] on wlan0
? (192.168.1.50) at <incomplete> on wlan0
router.lan (192.168.1.2) at AA:BB:CC:00:00:09 [ether] on wlan0
? (10.0.0.7) at 11:22:33:44:55:66 [ether] on eth1
"""

IP_NEIGH = """192.168.1.1 dev wlan0 lladdr aa:bb:cc:00:00:01 REACHABLE
192.168.1.77 dev wlan0  FAILED
fe80::1 dev wlan0 lladdr aa:bb:cc:00:00:01 router STALE
192.168.1.9 dev wlan0 lladdr 02:00:00:00:00:09 STALE
"""


class ParseArp(unittest.TestCase):
    def test_windows_output_keeps_real_devices_only(self):
        devices = scanner.parse_arp_output(WINDOWS_ARP, "192.168.1.")
        self.assertEqual(
            devices,
            [
                {"ip": "192.168.1.1", "mac": "aa:bb:cc:00:00:01"},
                {"ip": "192.168.1.20", "mac": "aa:bb:cc:00:00:02"},
            ],
        )

    def test_subnet_broadcast_is_not_a_device(self):
        # Regression: 192.168.1.255 / ff-ff-ff-ff-ff-ff appears in every Windows
        # ARP table and used to be reported as an unknown new device on each scan.
        ips = [d["ip"] for d in scanner.parse_arp_output(WINDOWS_ARP, "192.168.1.")]
        self.assertNotIn("192.168.1.255", ips)

    def test_multicast_and_zero_macs_dropped(self):
        text = "  192.168.1.40  01-00-5e-00-00-fb  static\n  192.168.1.41  00-00-00-00-00-00  dynamic\n"
        self.assertEqual(scanner.parse_arp_output(text, "192.168.1.") , [])

    def test_other_interfaces_filtered_by_prefix(self):
        ips = [d["ip"] for d in scanner.parse_arp_output(WINDOWS_ARP, "172.20.0.")]
        self.assertEqual(ips, ["172.20.0.2"])

    def test_duplicates_collapsed(self):
        devices = scanner.parse_arp_output(WINDOWS_ARP, "192.168.1.")
        self.assertEqual(len([d for d in devices if d["ip"] == "192.168.1.1"]), 1)

    def test_linux_arp_format(self):
        devices = scanner.parse_arp_output(LINUX_ARP, "192.168.1.")
        self.assertEqual(
            devices,
            [{"ip": "192.168.1.1", "mac": "aa:bb:cc:00:00:01"}, {"ip": "192.168.1.2", "mac": "aa:bb:cc:00:00:09"}],
        )

    def test_incomplete_entries_skipped(self):
        ips = [d["ip"] for d in scanner.parse_arp_output(LINUX_ARP, "192.168.1.")]
        self.assertNotIn("192.168.1.50", ips)

    def test_ip_neigh_format(self):
        devices = scanner.parse_arp_output(IP_NEIGH, "192.168.1.")
        # the FAILED entry has no MAC, the IPv6 line has no IPv4 address
        self.assertEqual(
            [d["ip"] for d in devices], ["192.168.1.1", "192.168.1.9"]
        )

    def test_random_wifi_macs_are_kept(self):
        # Phones use "locally administered" private MACs (second hex digit 2/6/a/e).
        # They are unicast, so they are real devices.
        text = "  192.168.1.30  da-a1-19-00-00-01  dynamic\n"
        self.assertEqual(len(scanner.parse_arp_output(text, "192.168.1.")), 1)

    def test_garbage_input(self):
        self.assertEqual(scanner.parse_arp_output("", "192.168.1."), [])
        self.assertEqual(scanner.parse_arp_output("not an arp table\n\n???", "192.168.1."), [])


class SubnetPrefix(unittest.TestCase):
    def _prefix_for(self, ip):
        fake_socket = mock.MagicMock()
        fake_socket.__enter__.return_value.getsockname.return_value = (ip, 1234)
        with mock.patch.object(scanner.socket, "socket", return_value=fake_socket):
            return scanner.get_local_subnet_prefix()

    def test_normal_address(self):
        self.assertEqual(self._prefix_for("192.168.1.5"), "192.168.1.")

    def test_unusable_addresses(self):
        self.assertIsNone(self._prefix_for("0.0.0.0"))
        self.assertIsNone(self._prefix_for("127.0.0.1"))

    def test_no_network(self):
        with mock.patch.object(scanner.socket, "socket", side_effect=OSError("unreachable")):
            self.assertIsNone(scanner.get_local_subnet_prefix())


class Subprocess(unittest.TestCase):
    def test_no_window_flag_is_passed_to_every_child_process(self):
        with mock.patch.object(scanner.subprocess, "run") as run:
            run.return_value = mock.Mock(stdout="", returncode=0)
            scanner._run_text(["arp", "-a"])
            scanner._ping_once("192.168.1.1")
        for call in run.call_args_list:
            self.assertEqual(call.kwargs["creationflags"], scanner._NO_WINDOW)

    def test_undecodable_output_does_not_crash(self):
        self.assertEqual(scanner._run_text(["definitely-not-a-real-command-xyz"]), "")

    def test_failures_become_empty_or_false(self):
        with mock.patch.object(scanner.subprocess, "run", side_effect=OSError("nope")):
            self.assertEqual(scanner._run_text(["arp", "-a"]), "")
            self.assertFalse(scanner._ping_once("192.168.1.1"))


class Enrichment(unittest.TestCase):
    def test_hostname_lookup_never_blocks_the_scan(self):
        import threading

        release = threading.Event()

        def slow(ip):
            release.wait(5)
            return "slow-host"

        with mock.patch.object(scanner, "_reverse_dns", side_effect=slow):
            names = scanner._resolve_hostnames(["192.168.1.1"], wait_seconds=0.05)
        release.set()
        self.assertEqual(names, {"192.168.1.1": None})

    def test_reverse_dns_that_returns_the_ip_is_no_name(self):
        with mock.patch.object(scanner.socket, "gethostbyaddr", return_value=("192.168.1.9", [], [])):
            self.assertIsNone(scanner._reverse_dns("192.168.1.9"))
        with mock.patch.object(scanner.socket, "gethostbyaddr", return_value=("printer.lan", [], [])):
            self.assertEqual(scanner._reverse_dns("192.168.1.9"), "printer.lan")
        with mock.patch.object(scanner.socket, "gethostbyaddr", side_effect=OSError):
            self.assertIsNone(scanner._reverse_dns("192.168.1.9"))

    def test_enrich_sorts_by_ip_and_keeps_fields(self):
        raw = [{"ip": "192.168.1.100", "mac": "aa:aa:aa:00:00:01"}, {"ip": "192.168.1.9", "mac": "aa:aa:aa:00:00:02"}]
        with mock.patch.object(scanner, "_check_telnet_open", side_effect=lambda ip: ip.endswith(".9")), \
                mock.patch.object(scanner, "_resolve_hostnames", return_value={"192.168.1.9": "nas.lan"}):
            out = scanner.enrich_devices(raw)
        self.assertEqual([d["ip"] for d in out], ["192.168.1.9", "192.168.1.100"])
        self.assertEqual(out[0], {"ip": "192.168.1.9", "mac": "aa:aa:aa:00:00:02", "hostname": "nas.lan", "telnet_open": True})
        self.assertEqual(out[1]["hostname"], None)
        self.assertFalse(out[1]["telnet_open"])

    def test_scan_without_a_network_gives_a_clear_error(self):
        with mock.patch.object(scanner, "get_local_subnet_prefix", return_value=None):
            with self.assertRaises(RuntimeError) as ctx:
                scanner.scan_network()
        self.assertIn("local network", str(ctx.exception))

    def test_scan_wires_the_steps_together(self):
        with mock.patch.object(scanner, "get_local_subnet_prefix", return_value="192.168.1."), \
                mock.patch.object(scanner, "_sweep_subnet") as sweep, \
                mock.patch.object(scanner, "read_arp_table", return_value=[{"ip": "192.168.1.1", "mac": "aa:bb:cc:00:00:01"}]), \
                mock.patch.object(scanner, "_check_telnet_open", return_value=False), \
                mock.patch.object(scanner, "_resolve_hostnames", return_value={}):
            devices = scanner.scan_network()
        sweep.assert_called_once_with("192.168.1.")
        self.assertEqual(len(devices), 1)


if __name__ == "__main__":
    unittest.main()
