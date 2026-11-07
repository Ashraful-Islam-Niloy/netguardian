"""Tests for checks, the known-devices list, the report and the CLI."""
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from netguardian.core.checks import run_all_checks
from netguardian.core.known_devices import (
    add_known_device,
    add_known_devices,
    default_path,
    known_macs_set,
    load_known_devices,
    normalize_mac,
    save_known_devices,
)
from netguardian.core.reporter import generate_markdown_report
from netguardian.demo_data import DEMO_DEVICES, DEMO_KNOWN_MACS

CLEAN = [
    {"ip": "192.168.1.1", "mac": "aa:bb:cc:00:00:01", "hostname": "router.home", "telnet_open": False},
    {"ip": "192.168.1.20", "mac": "aa:bb:cc:00:00:02", "hostname": None, "telnet_open": False},
]


class Checks(unittest.TestCase):
    def test_clean_network_has_no_findings(self):
        report = run_all_checks(CLEAN, {"aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02"})
        self.assertEqual(report.findings, [])

    def test_demo_findings(self):
        report = run_all_checks(DEMO_DEVICES, DEMO_KNOWN_MACS)
        self.assertEqual(sorted(f.check_id for f in report.findings), ["new_device", "new_device", "telnet_open"])

    def test_unknown_devices_are_new(self):
        report = run_all_checks(CLEAN, set())
        self.assertEqual([f.check_id for f in report.findings], ["new_device", "new_device"])

    def test_known_list_matches_whatever_the_mac_notation(self):
        report = run_all_checks(CLEAN, {"AA-BB-CC-00-00-01", " aa:bb:cc:00:00:02 "})
        self.assertEqual(report.findings, [])

    def test_device_without_mac_is_ignored_not_guessed(self):
        report = run_all_checks([{"ip": "192.168.1.9", "mac": None, "telnet_open": False}], set())
        self.assertEqual(report.findings, [])

    def test_telnet_flagged_high_even_for_known_device(self):
        devices = [{"ip": "192.168.1.9", "mac": "aa:aa:aa:00:00:09", "telnet_open": True}]
        report = run_all_checks(devices, {"aa:aa:aa:00:00:09"})
        self.assertEqual([(f.check_id, f.severity) for f in report.findings], [("telnet_open", "high")])

    def test_empty_inputs(self):
        self.assertEqual(run_all_checks([], set()).findings, [])


class KnownDevices(unittest.TestCase):
    def test_normalize(self):
        self.assertEqual(normalize_mac(" AA-BB-CC-00-00-01 "), "aa:bb:cc:00:00:01")

    def test_add_does_not_mutate(self):
        original = {}
        updated = add_known_device(original, "AA:BB:CC:00:00:01", "tv")
        self.assertEqual(original, {})
        self.assertEqual(updated, {"aa:bb:cc:00:00:01": {"label": "tv"}})

    def test_add_all_keeps_existing_labels_and_skips_macless(self):
        known = {"aa:bb:cc:00:00:01": {"label": "My router"}}
        devices = CLEAN + [{"ip": "192.168.1.9", "mac": None}]
        updated = add_known_devices(known, devices)
        self.assertEqual(updated["aa:bb:cc:00:00:01"]["label"], "My router")
        self.assertEqual(updated["aa:bb:cc:00:00:02"]["label"], "192.168.1.20")  # no hostname: falls back to the IP
        self.assertEqual(len(updated), 2)

    def test_round_trip_and_no_temp_file_left(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "nested" / "known.json")
            known = add_known_devices({}, CLEAN)
            save_known_devices(path, known)
            self.assertEqual(load_known_devices(path), known)
            self.assertEqual(known_macs_set(load_known_devices(path)), {"aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02"})
            self.assertEqual(os.listdir(Path(path).parent), ["known.json"])

    def test_missing_or_damaged_files_give_an_empty_list(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(load_known_devices(str(Path(tmp) / "nope.json")), {})
            for content in ("not json", "[1, 2, 3]", '"text"', "42", "null", ""):
                path = Path(tmp) / "bad.json"
                path.write_text(content, encoding="utf-8")
                self.assertEqual(load_known_devices(str(path)), {}, content)
            path = Path(tmp) / "binary.json"
            path.write_bytes(b"\xff\xfe\x00\x80")
            self.assertEqual(load_known_devices(str(path)), {})

    def test_default_path_is_per_user_not_cwd(self):
        p = Path(default_path())
        self.assertTrue(p.is_absolute())
        self.assertEqual(p.name, "known-devices.json")
        from netguardian.core.known_devices import _windows_default

        appdata = _windows_default(r"C:\Users\x\AppData\Roaming", Path("/home/x"))
        self.assertTrue(appdata.startswith(r"C:\Users\x\AppData\Roaming"))
        self.assertTrue(appdata.endswith("known-devices.json"))
        self.assertIn("NetGuardian", _windows_default(None, Path("/home/x")))


class Report(unittest.TestCase):
    def test_report_written_with_devices_and_issues(self):
        report = run_all_checks(DEMO_DEVICES, DEMO_KNOWN_MACS)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "deep" / "report.md"
            text = generate_markdown_report(DEMO_DEVICES, report, str(path))
            self.assertEqual(path.read_text(encoding="utf-8"), text)
        self.assertIn("# NetGuardian Report", text)
        self.assertIn("192.168.1.60", text)
        self.assertIn("[HIGH]", text)


@unittest.skipUnless(__import__("importlib").util.find_spec("rich"), "rich not installed")
class Cli(unittest.TestCase):
    def _run(self, argv):
        from netguardian import cli

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            cli.console.file = out
            code = cli.main(argv)
        return code, out.getvalue()

    def test_demo(self):
        code, out = self._run(["demo"])
        self.assertEqual(code, 0)
        self.assertIn("5 device(s), 3 issue(s)", out)

    def test_scan_marks_all_known_and_second_scan_is_quiet(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch("netguardian.cli.scan_network", return_value=CLEAN):
            known = str(Path(tmp) / "known.json")
            argv = ["scan", "--out", tmp, "--known", known]
            code, out = self._run(argv)
            self.assertEqual(code, 0)
            self.assertIn("First scan", out)
            self.assertIn("2 device(s), 2 issue(s)", out)

            code, out = self._run(argv + ["--mark-all-known"])
            self.assertEqual(code, 0)
            self.assertIn("2 device(s), 0 issue(s)", out)
            self.assertEqual(len(json.loads(Path(known).read_text(encoding="utf-8"))), 2)

            code, out = self._run(argv)
            self.assertIn("2 device(s), 0 issue(s)", out)
            self.assertNotIn("First scan", out)
            self.assertTrue((Path(tmp) / "netguardian-report.md").exists())

    def test_scan_without_network_is_a_message_not_a_traceback(self):
        with mock.patch("netguardian.cli.scan_network", side_effect=RuntimeError("Couldn't determine your local network.")):
            code, out = self._run(["scan"])
        self.assertEqual(code, 1)
        self.assertIn("Couldn't determine", out)


if __name__ == "__main__":
    unittest.main()
