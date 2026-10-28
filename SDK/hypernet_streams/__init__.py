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
from dataclasses import dataclass
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

    def sendall(self, data: bytes) -> None:
        self.socket.sendall(data)

    def recv(self, maximum: int = 65536) -> bytes:
        return self.socket.recv(maximum)

    def shutdown_write(self) -> None:
        """Send EOF while retaining the ability to receive the peer's response."""
        self.socket.shutdown(socket.SHUT_WR)

    def close(self) -> None:
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

    def __init__(self, directory: str | os.PathLike[str]):
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
        request = {"version": 1, "action": action, "timeoutMs": int(timeout * 1000), **fields}
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
            if not isinstance(response, dict) or response.get("version") != 1 or not isinstance(response.get("ok"), bool):
                raise AgentError("Protocol", "unexpected companion response")
            if not response["ok"]:
                error = response.get("error", {})
                raise AgentError(str(error.get("code", "Refused")), str(error.get("message", "companion refused request")))
            stream.settimeout(None)
            return response, stream
        except BaseException:
            stream.close()
            raise

    @staticmethod
    def _stream(response: dict[str, Any], stream: socket.socket) -> Stream:
        if not isinstance(response.get("peer"), dict) or not isinstance(response.get("id"), str):
            stream.close()
            raise AgentError("Protocol", "stream response lacks its verified peer context")
        return Stream(stream, response["peer"], response["id"])

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

    def status(self) -> dict[str, Any]:
        response, stream = self._request("status")
        stream.close()
        return response

    def cancel(self, connection_id: str) -> dict[str, Any]:
        response, stream = self._request("cancel", id=connection_id)
        stream.close()
        return response
