from .base import FlowDissector
from .dnp3 import Dnp3Dissector
from .iec104 import Iec104Dissector
from .identify import WELL_KNOWN_TCP, WELL_KNOWN_UDP, identify
from .modbus import ModbusDissector
from .s7comm import S7Dissector

def function_names(protocol: str) -> frozenset:
    """Names a dissector can emit as ``ProtoMessage.function`` for non-session requests.

    ``UNKNOWN_<n>`` placeholders (undefined codes) are accepted separately by callers.
    """
    from . import dnp3, iec104, modbus, s7comm

    if protocol == "modbus":
        return frozenset(v[0] for v in modbus.FUNCTIONS.values())
    if protocol == "dnp3":
        return frozenset(dnp3.APP_FUNCTIONS.values())
    if protocol == "s7comm":
        return frozenset(v[0] for v in s7comm.FUNCTIONS.values()) | s7comm.USERDATA_FUNCTIONS
    if protocol == "iec104":
        return frozenset(v[0] for v in iec104.TYPES.values())
    return frozenset()


# behavioural tags usable as "@tag" in policy function lists
FUNCTION_KINDS = frozenset(["read", "write", "control", "critical", "diagnostic", "maintenance", "discovery",
                            "file_transfer", "program_transfer", "monitor"])

DISSECTORS = {"modbus": ModbusDissector, "dnp3": Dnp3Dissector, "s7comm": S7Dissector, "iec104": Iec104Dissector}

__all__ = ["function_names", "FUNCTION_KINDS", "FlowDissector", "ModbusDissector", "Dnp3Dissector", "S7Dissector", "Iec104Dissector", "DISSECTORS",
           "identify", "WELL_KNOWN_TCP", "WELL_KNOWN_UDP"]
