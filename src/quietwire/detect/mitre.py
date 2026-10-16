"""MITRE ATT&CK for ICS technique catalogue used by the rule set.

Verified against https://attack.mitre.org/matrices/ics (ATT&CK content v19.2) on
2026-10-04. Note: in v19 the former T0855 "Unauthorized Command Message" and
T0856 "Spoof Reporting Message" were merged into T1692 "Unauthorized Message"
(sub-techniques T1692.001 Command Message / T1692.002 Reporting Message); the
retired IDs are deliberately not used.
"""

from __future__ import annotations

ATTACK_ICS_VERSION = "v19"
VERIFIED_ON = "2026-10-04"

TECHNIQUES = {
    "T0814": "Denial of Service",
    "T0816": "Device Restart/Shutdown",
    "T0836": "Modify Parameter",
    "T0843": "Program Download",
    "T0845": "Program Upload",
    "T0846": "Remote System Discovery",
    "T0848": "Rogue Master",
    "T0858": "Change Operating Mode",
    "T0881": "Service Stop",
    "T0885": "Commonly Used Port",
    "T0888": "Remote System Information Discovery",
    "T0889": "Modify Program",
    "T1692.001": "Unauthorized Message: Command Message",
    "T1692.002": "Unauthorized Message: Reporting Message",
}


def technique_name(tid: str) -> str:
    return TECHNIQUES.get(tid, tid)
