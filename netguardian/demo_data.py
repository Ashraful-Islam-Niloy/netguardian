"""Sample scan results for `netguardian demo` and for testing."""
from __future__ import annotations

DEMO_DEVICES = [
    {"ip": "192.168.1.1", "mac": "aa:bb:cc:00:00:01", "hostname": "router.home", "telnet_open": False},
    {"ip": "192.168.1.20", "mac": "aa:bb:cc:00:00:02", "hostname": "desktop-pc", "telnet_open": False},
    {"ip": "192.168.1.35", "mac": "aa:bb:cc:00:00:03", "hostname": "iphone-alex", "telnet_open": False},
    {"ip": "192.168.1.60", "mac": "88:77:66:11:22:33", "hostname": None, "telnet_open": True},
    {"ip": "192.168.1.75", "mac": "de:ad:be:ef:00:99", "hostname": "smart-plug-2", "telnet_open": False},
]

# The user has previously confirmed these three as their own devices —
# the other two should show up as "new" in the demo.
DEMO_KNOWN_MACS = {"aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02", "aa:bb:cc:00:00:03"}
