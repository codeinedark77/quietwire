"""Dissector interface shared by all protocol decoders."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List

from ..model import Anomaly, ProtoMessage

# Hard cap on malformed pseudo-messages emitted from a single feed() call, so a
# hostile or garbage stream cannot make us allocate unbounded objects.
MAX_MALFORMED_PER_FEED = 8


def malformed(protocol: str, is_request: bool, code: str, message: str, size: int = 0) -> ProtoMessage:
    return ProtoMessage(
        protocol=protocol,
        is_request=is_request,
        function="MALFORMED",
        kinds=frozenset(["malformed"]),
        size=size,
        anomalies=[Anomaly(code, message)],
    )


class FlowDissector(ABC):
    """Stateful per-flow decoder.

    ``from_client`` is True for the direction originated by the flow's client
    (TCP initiator / UDP first sender or well-known-port client).  Protocols
    that carry their own role information (DNP3 DIR bit) may override the
    sender role in the returned messages.
    """

    protocol: str = ""

    @abstractmethod
    def feed_stream(self, from_client: bool, data: bytes, gap: bool) -> List[ProtoMessage]:
        """Consume in-order TCP bytes. ``gap`` means bytes were lost before ``data``."""

    def feed_datagram(self, from_client: bool, data: bytes) -> List[ProtoMessage]:
        """Consume one UDP datagram (self-contained)."""
        msgs = self.feed_stream(from_client, data, True)
        self.reset(from_client)
        return msgs

    @abstractmethod
    def reset(self, from_client: bool) -> None:
        """Drop buffered partial data for one direction."""
