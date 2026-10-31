# SPDX-License-Identifier: MIT
"""Verified application streams through the local HyperNetSuite companion.

Cryptography, authority floors, transport and peer verification remain in the
companion. This Linux SDK exchanges bounded local control frames and raw bytes.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import stat
import struct
from dataclasses import dataclass, field
import weakref
import threading

from .context import (AuthorityCapability, AuthorityCheck, AuthorityObservation, CompanionStatus, ConnectionStatus, Disposition, boot_ms, digest, integer)
from typing import Any

_MAXIMUM = 16384


class AgentError(RuntimeError):
    """A local protocol, ownership, capacity or authority failure."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _exact(stream: socket.socket, length: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < length:
        part = stream.recv(length - len(chunks))
        if not part:
            raise AgentError("Closed", "companion closed before its response completed")
        chunks.extend(part)
    return bytes(chunks)


def _private(path: Path, kind: int) -> os.stat_result:
    info = path.lstat()
    if stat.S_IFMT(info.st_mode) != kind or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != (0o700 if kind == stat.S_IFDIR else 0o600):
        raise AgentError("Ownership", "companion directory/socket must be private and owned by this user")
    return info


def _identity(info: os.stat_result) -> tuple[int, int]:
    return info.st_dev, info.st_ino


@dataclass
class Stream:
    """A raw duplex socket and its separately verified peer context."""

    socket: socket.socket
    peer: dict[str, Any]
    id: str
    privacy: dict[str, Any] | None = None
    check_authority: bool = False
    _authority_epoch: int = 0
    _state_lock: Any = field(default_factory=threading.RLock, repr=False, compare=False)

    def sendall(self, data: bytes) -> None:
        self.socket.sendall(data)

    def recv(self, maximum: int = 65536) -> bytes:
        return self.socket.recv(maximum)

    def shutdown_write(self) -> None:
        """Send EOF while retaining the ability to receive the peer's response."""
        self.socket.shutdown(socket.SHUT_WR)

    def close(self) -> None:
        with self._state_lock:
            self._authority_epoch += 1
        try:
            self.socket.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.socket.close()

    def __enter__(self) -> Stream:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class Agent:
    """A client for one owner-private companion directory.

    Incoming `peer["principal"]` identifies the authenticated remote caller.
    Applications must apply their own authorization before handling payloads.
    Outgoing contexts identify the exact service, owner and TLS endpoint.
    """

    def __init__(self, directory: str | os.PathLike[str], *, version: int = 1):
        if type(version) is not int or version not in (1, 2):
            raise ValueError("supported companion versions are1 and2")
        self.version = version
        self._state_lock = threading.RLock()
        self._streams: weakref.WeakValueDictionary[str, Stream] = weakref.WeakValueDictionary()
        self._control: tuple[str | None, str | None, int | None] | None = None
        self.directory = Path(directory)
        if not self.directory.is_absolute() or self.directory.resolve() != self.directory:
            raise AgentError("Path", "companion directory must be an absolute canonical path")

    def _socket(self) -> socket.socket:
        directory = _private(self.directory, stat.S_IFDIR)
        path = self.directory / "Control.sock"
        before = _private(path, stat.S_IFSOCK)
        stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            stream.settimeout(5)
            stream.connect(str(path))
            _, uid, _ = struct.unpack("3i", stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid != os.geteuid():
                raise AgentError("Ownership", "companion has another Unix peer owner")
            if _identity(before) != _identity(_private(path, stat.S_IFSOCK)) or _identity(directory) != _identity(_private(self.directory, stat.S_IFDIR)):
                raise AgentError("Changed", "companion directory or socket changed during connection")
            return stream
        except BaseException:
            stream.close()
            raise

    def _request(self, action: str, *, timeout: float = 30, **fields: Any) -> tuple[dict[str, Any], socket.socket]:
        if not 0.1 <= timeout <= 60:
            raise ValueError("local control timeout must be 0.1..60 seconds")
        request = {"version": self.version, "action": action, "timeoutMs": int(timeout * 1000), **fields}
        body = json.dumps(request, separators=(",", ":"), allow_nan=False).encode("utf-8")
        if not 0 < len(body) <= _MAXIMUM:
            raise AgentError("Frame", "local request exceeds its bound")
        stream = self._socket()
        try:
            stream.settimeout(timeout + 5)
            stream.sendall(struct.pack("!I", len(body)) + body)
            length = struct.unpack("!I", _exact(stream, 4))[0]
            if not 0 < length <= _MAXIMUM:
                raise AgentError("Frame", "local response exceeds its bound")
            response = json.loads(_exact(stream, length))
            if not isinstance(response, dict) or response.get("version") != self.version or not isinstance(response.get("ok"), bool):
                raise AgentError("Protocol", "unexpected companion response")
            if not response["ok"]:
                error = response.get("error", {})
                raise AgentError(str(error.get("code", "Refused")), str(error.get("message", "companion refused request")))
            stream.settimeout(None)
            return response, stream
        except BaseException:
            stream.close()
            raise

    def _stream(self, response: dict[str, Any], stream: socket.socket) -> Stream:
        if not isinstance(response.get("peer"), dict) or not isinstance(response.get("id"), str):
            stream.close()
            raise AgentError("Protocol", "stream response lacks its verified peer context")
        result = Stream(stream, response["peer"], response["id"])
        if self.version == 2:
            if not isinstance(response.get("privacy"), dict) or type(response.get("checkAuthority")) is not bool:
                stream.close()
                raise AgentError("Protocol", "v2 stream lacks directional context")
            result.privacy = response["privacy"]
            result.check_authority = response["checkAuthority"]
        result._state_lock = self._state_lock
        with self._state_lock:
            self._streams[result.id] = result
        return result

    def connect(self, service: str, protocol: str | None = None, *, timeout: float = 30) -> Stream:
        """Connect an operator-configured service; no remote address can be supplied."""
        response, stream = self._request("connect", service=service, protocol=protocol, timeout=timeout)
        return self._stream(response, stream)

    def accept(self, *, timeout: float | None = None) -> Stream:
        """Wait for a verified incoming connection; None uses bounded repeated waits."""
        while True:
            try:
                response, stream = self._request("accept", timeout=60 if timeout is None else timeout)
                return self._stream(response, stream)
            except AgentError as error:
                if timeout is None and error.code == "Timeout":
                    continue
                raise

    def status(self) -> dict[str, Any] | CompanionStatus:
        response, stream = self._request("status")
        stream.close()
        if self.version == 1:
            return response
        try:
            status = CompanionStatus.parse(response)
        except (KeyError, TypeError, ValueError) as error:
            raise AgentError("Protocol", "invalid typed companion status") from error
        with self._state_lock:
            self._observe_control(status.check_authority.identity)
            active = {item.id for item in status.connections if item.check_authority}
            for connection in self._streams.values():
                if connection.id not in active or not status.check_authority.endpoint_ready:
                    connection._authority_epoch += 1
        return status

    def capabilities(self) -> AuthorityCapability:
        """Distinguish API support, endpoint readiness, and each connection's capability."""
        if self.version != 2:
            raise AgentError("UnsupportedVersion", "typed authority capability requires version2")
        return self.status().check_authority

    def _observe_control(self, identity: tuple[str | None, str | None, int | None]) -> None:
        with self._state_lock:
            if identity != self._control:
                for connection in self._streams.values():
                    connection._authority_epoch += 1
                self._control = identity

    def cancel(self, connection_id: str) -> dict[str, Any]:
        response, stream = self._request("cancel", id=connection_id)
        stream.close()
        with self._state_lock:
            connection = self._streams.get(connection_id)
            if connection is not None:
                connection._authority_epoch += 1
        return response


    def check_authority(self, connection: Stream, action_digest: bytes, *, timeout: float = 1.0) -> AuthorityCheck:
        """Check one exact incoming session for this action; recheck every queued action.

        `action_digest` binds application-defined canonical action bytes. HyperNet
        checks transport authority; the application still checks its own current
        permissions and ordering. A returned receipt cannot be retracted after an
        unobserved remote disconnect and is never a reusable grant.
        """
        if self.version != 2:
            raise AgentError("UnsupportedVersion", "authority checks require version2")
        if not isinstance(action_digest, bytes) or len(action_digest) != 32 or not any(action_digest):
            raise ValueError("action_digest must be32 nonzero digest bytes")
        if not 0.1 <= timeout <= 5:
            raise ValueError("authority timeout must be0.1..5 seconds")
        offsets = Path("/proc/self/timens_offsets").read_text().splitlines()
        if [line.split() for line in offsets] != [["monotonic", "0", "0"], ["boottime", "0", "0"]]:
            raise AgentError("Clock", "authority checks require unshifted boot time")
        started = boot_ms()
        usable_deadline = started + int(timeout * 1000)
        nonce = os.urandom(32).hex()
        action = action_digest.hex()
        # Every new check consumes the prior observation for this connection.
        with self._state_lock:
            if self._streams.get(connection.id) is not connection or connection.socket.fileno() < 0:
                raise AgentError("NotActive", "stream is not active on this SDK client")
            connection._authority_epoch += 1
            epoch = connection._authority_epoch
            original_control = self._control
        try:
            response, control = self._request("checkAuthority", id=connection.id, nonce=nonce, actionDigest=action, timeout=timeout)
        except (OSError, AgentError) as error:
            if isinstance(error, AgentError) and error.code != "Closed":
                raise
            disposition = Disposition.EXPIRED if boot_ms() >= usable_deadline else Disposition.UNAVAILABLE
            return AuthorityCheck(disposition=disposition, id=connection.id, nonce=nonce, action_digest=action, authority=None,
                                  companion_started_boot_ms=0, companion_deadline_boot_ms=0, receipt_not_after_boot_ms=0,
                                  usable_until_boot_ms=usable_deadline, _stream=connection, _epoch=epoch)
        control.close()
        try:
            if response["id"] != connection.id or response["nonce"] != nonce or response["actionDigest"] != action:
                raise ValueError("authority correlation differs")
            value = response["result"]
            disposition = Disposition(value["disposition"])
            receipt_disposition = disposition
            begin = integer(value["callerStartedBootMs"])
            end = integer(value["callerDeadlineBootMs"])
            not_after = integer(value["notAfterBootMs"])
            if begin < started or end <= begin or end - begin != int(timeout * 1000) or not_after > end:
                raise ValueError("authority deadline differs")
            observation = None if value["authority"] is None else AuthorityObservation.parse(value["authority"])
            if (disposition in (Disposition.PERMITTED, Disposition.DENIED)) != (observation is not None):
                raise ValueError("authority disposition lacks its certification")
            if observation is not None:
                if (observation.code == 0) != (disposition is Disposition.PERMITTED) or not_after <= begin:
                    raise ValueError("authority result disagrees with its certified code")
                if observation.network != connection.peer["network"] or observation.incarnation != connection.peer["incarnation"]:
                    raise ValueError("authority belongs to another network")
            identity = (value.get("companionInstance"), value.get("endpointInstance"), value.get("controlGeneration"))
            has_identity = observation is not None or value.get("session") is not None
            if has_identity:
                if digest(value["session"]) != connection.peer["session"] or integer(value["generation"]) != connection.peer["generation"]:
                    raise ValueError("authority belongs to another stream")
                digest(identity[0]); digest(identity[1])
                if not integer(identity[2]) or not isinstance(value["kernelBoot"], str) or len(value["kernelBoot"]) != 36:
                    raise ValueError("invalid authority endpoint identity")
            with self._state_lock:
                context_current = connection._authority_epoch == epoch and self._control == original_control and connection.socket.fileno() >= 0
                if has_identity and context_current:
                    self._observe_control(identity)
                    epoch = connection._authority_epoch
                usable_deadline = min(usable_deadline, not_after)
                if not context_current:
                    disposition = Disposition.NOT_ACTIVE
                    usable_deadline = 0
                elif boot_ms() >= usable_deadline and observation is not None:
                    disposition = Disposition.EXPIRED
                result = AuthorityCheck(disposition=disposition, id=connection.id, nonce=nonce, action_digest=action, authority=observation,
                                        companion_started_boot_ms=begin, companion_deadline_boot_ms=end, receipt_not_after_boot_ms=not_after,
                                        usable_until_boot_ms=usable_deadline, receipt_disposition=receipt_disposition,
                                        session=value.get("session"), generation=value.get("generation"), companion_instance=identity[0],
                                        endpoint_instance=identity[1], control_generation=identity[2], kernel_boot=value.get("kernelBoot"),
                                        privacy=value.get("privacy"), _stream=connection, _epoch=epoch)
                if context_current and result.privacy is not None:
                    connection.privacy = result.privacy
                return result
        except (KeyError, TypeError, ValueError) as error:
            raise AgentError("Protocol", "invalid correlated authority result") from error
