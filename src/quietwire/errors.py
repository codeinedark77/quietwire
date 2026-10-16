"""Exception types raised by quietwire."""


class QuietwireError(Exception):
    """Base class for all quietwire errors."""


class CaptureFormatError(QuietwireError):
    """The capture file is not a supported/valid pcap or pcapng file."""


class PolicyError(QuietwireError):
    """The policy file is missing, unparsable or fails validation."""


class AuditLogError(QuietwireError):
    """The audit log is unreadable or failed integrity verification."""
