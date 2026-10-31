# SPDX-License-Identifier: MIT
"""Typed v2 companion context. Results are bounded observations, never reusable grants."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import time
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from . import Stream


def boot_ms() -> int:
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME) // 1_000_000


def integer(value: Any) -> int:
    if type(value) is not int or not 0 <= value < 2**64:
        raise ValueError("expected unsigned integer")
    return value


def digest(value: Any) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ValueError("expected32 lowercase hex bytes")
    return value


class Disposition(str, Enum):
    PERMITTED = "permitted"
    DENIED = "denied"
    UNAVAILABLE = "unavailable"
    EXPIRED = "expired"
    NOT_ACTIVE = "notActive"


@dataclass(frozen=True)
class AuthorityCapability:
    supported: bool
    endpoint_ready: bool
    companion_instance: str | None
    endpoint_instance: str | None
    control_generation: int | None

    @classmethod
    def parse(cls, value: dict[str, Any]) -> AuthorityCapability:
        if type(value["supported"]) is not bool or type(value["endpointReady"]) is not bool or value["capability"] != "checkAuthority-v2":
            raise ValueError("invalid authority capability")
        companion = value.get("companionInstance")
        endpoint = value.get("endpointInstance")
        generation = value.get("controlGeneration")
        if companion is not None:
            digest(companion)
        if endpoint is not None:
            digest(endpoint)
        if generation is not None:
            integer(generation)
        if value["endpointReady"] and (companion is None or endpoint is None or not generation):
            raise ValueError("ready endpoint lacks its exact control identity")
        return cls(value["supported"], value["endpointReady"], companion, endpoint, generation)

    @property
    def identity(self) -> tuple[str | None, str | None, int | None]:
        return self.companion_instance, self.endpoint_instance, self.control_generation


@dataclass(frozen=True)
class ConnectionStatus:
    id: str
    direction: str
    check_authority: bool
    privacy: dict[str, Any]


@dataclass(frozen=True)
class CompanionStatus:
    check_authority: AuthorityCapability
    connections: tuple[ConnectionStatus, ...]
    raw: dict[str, Any] = field(repr=False)

    @classmethod
    def parse(cls, value: dict[str, Any]) -> CompanionStatus:
        capability = AuthorityCapability.parse(value["capabilities"]["checkAuthority"])
        connections = []
        for item in value["connections"]:
            if item["direction"] not in ("incoming", "outgoing") or type(item["checkAuthority"]) is not bool or not isinstance(item["privacy"], dict):
                raise ValueError("invalid connection capability")
            connections.append(ConnectionStatus(digest(item["id"]), item["direction"], item["checkAuthority"], item["privacy"]))
        return cls(capability, tuple(connections), value)


@dataclass(frozen=True)
class AuthorityObservation:
    network: str
    incarnation: str
    configuration: str
    epoch: int
    height: int
    state: str
    statement_digest: str
    evaluated_at_ms: int
    expires_at_ms: int
    code: int

    @classmethod
    def parse(cls, value: dict[str, Any]) -> AuthorityObservation:
        result = cls(digest(value["network"]), digest(value["incarnation"]), digest(value["configuration"]), integer(value["epoch"]), integer(value["height"]), digest(value["state"]), digest(value["statementDigest"]), integer(value["evaluatedAtMs"]), integer(value["expiresAtMs"]), integer(value["code"]))
        if result.expires_at_ms <= result.evaluated_at_ms:
            raise ValueError("invalid authority observation lifetime")
        return result


@dataclass(frozen=True)
class AuthorityCheck:
    disposition: Disposition
    id: str
    nonce: str
    action_digest: str
    authority: AuthorityObservation | None
    companion_started_boot_ms: int
    companion_deadline_boot_ms: int
    receipt_not_after_boot_ms: int
    usable_until_boot_ms: int
    receipt_disposition: Disposition | None = None
    session: str | None = None
    generation: int | None = None
    companion_instance: str | None = None
    endpoint_instance: str | None = None
    control_generation: int | None = None
    kernel_boot: str | None = None
    privacy: dict[str, Any] | None = None
    _stream: Stream | None = field(default=None, repr=False, compare=False)
    _epoch: int = field(default=0, repr=False, compare=False)

    @property
    def certified(self) -> bool:
        return self.authority is not None

    @property
    def usable(self) -> bool:
        """Check the deadline and locally observed closure, not an unobserved remote state."""
        if not self.certified or self._stream is None:
            return False
        with self._stream._state_lock:
            return boot_ms() < self.usable_until_boot_ms and self._stream.socket.fileno() >= 0 and self._stream._authority_epoch == self._epoch

    @property
    def permitted(self) -> bool:
        return self.disposition is Disposition.PERMITTED and self.usable
