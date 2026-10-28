#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Serve authenticated echo/events and immutable file ranges through HyperNet."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import sys

from hypernet_streams import Agent


MAX_RANGE = 128 * 1024 * 1024


def exact(stream, length):
    result = bytearray()
    while len(result) < length:
        part = stream.recv(length - len(result))
        if not part:
            raise EOFError("stream ended before its declared response")
        result.extend(part)
    return bytes(result)


def header(stream, value=None):
    if value is not None:
        body = json.dumps(value, separators=(",", ":")).encode()
        if not 0 < len(body) <= 4096:
            raise ValueError("header exceeds bound")
        stream.sendall(struct.pack("!I", len(body)) + body)
        return
    length = struct.unpack("!I", exact(stream, 4))[0]
    if not 0 < length <= 4096:
        raise ValueError("header exceeds bound")
    value = json.loads(exact(stream, length))
    if not isinstance(value, dict):
        raise ValueError("header must be an object")
    return value


def digest(path):
    with path.open("rb") as source:
        result = hashlib.sha256()
        while data := source.read(1024 * 1024):
            result.update(data)
        return result.hexdigest()


def identity(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def principal(value):
    # The SDK context keeps the authenticated public-key identifier separate from payload.
    return bytes(value).hex() if isinstance(value, list) else value


def serve(args):
    agent = Agent(args.agent)
    source = args.file.resolve(strict=True) if args.file else None
    signature = identity(source.stat()) if source else None
    object_digest = digest(source) if source else None
    if source and identity(source.stat()) != signature:
        raise ValueError("source changed during its initial hash")
    print(json.dumps({"status": "Ready", "sha256": object_digest,
                      "size": signature[2] if signature else None}), flush=True)
    while True:
        with agent.accept() as stream:
            try:
                if principal(stream.peer.get("principal")) not in args.allow_principal:
                    raise PermissionError("caller is not in this application's allow list")
                request = header(stream)
                operation = request.get("operation")
                if operation == "echo":
                    message = request.get("message")
                    if not isinstance(message, str) or len(message.encode()) > 2048:
                        raise ValueError("echo message exceeds bound")
                    header(stream, {"ok": True, "event": "echo", "message": message})
                elif operation == "range":
                    offset, length = request.get("offset"), request.get("length")
                    if not source or request.get("sha256") != object_digest:
                        raise ValueError("immutable object identity is unavailable")
                    if type(offset) is not int or type(length) is not int or not (
                            0 <= offset < signature[2] and 0 < length <= MAX_RANGE
                            and offset + length <= signature[2]):
                        raise ValueError("range is outside the immutable object")
                    with source.open("rb") as content:
                        if identity(os.fstat(content.fileno())) != signature:
                            raise ValueError("source changed after publication")
                        content.seek(offset)
                        header(stream, {"ok": True, "sha256": object_digest,
                                        "size": signature[2], "offset": offset, "length": length})
                        remaining = length
                        while remaining:
                            data = content.read(min(65536, remaining))
                            if not data:
                                raise EOFError("source ended during range")
                            stream.sendall(data)
                            remaining -= len(data)
                        if identity(os.fstat(content.fileno())) != signature:
                            raise ValueError("source changed during range")
                else:
                    raise ValueError("unsupported application operation")
                stream.shutdown_write()
            except (OSError, ValueError, EOFError) as error:
                # No control JSON may be inserted into a partly sent range body.
                print(json.dumps({"refused": str(error), "connection": stream.id}),
                      file=sys.stderr, flush=True)


def echo(args):
    with Agent(args.agent).connect(args.service, "example/1") as stream:
        header(stream, {"operation": "echo", "message": args.message})
        stream.shutdown_write()
        response = header(stream)
        if response != {"ok": True, "event": "echo", "message": args.message}:
            raise ValueError("echo response differs")
        print(json.dumps({"peer": stream.peer, "response": response}))


def download(args):
    if len(bytes.fromhex(args.sha256)) != 32 or args.size <= 0:
        raise ValueError("supply independently verified SHA256 and object size")
    if not 1 <= args.range_bytes <= MAX_RANGE:
        raise ValueError("range must be 1..134217728 bytes")
    target = args.output.absolute()
    if target.exists():
        raise FileExistsError("destination already exists")
    part, metadata = target.with_name(target.name + ".partial"), target.with_name(target.name + ".partial.json")
    expected = {"sha256": args.sha256, "size": args.size}
    if metadata.exists():
        if json.loads(metadata.read_text()) != expected or not part.is_file():
            raise ValueError("resume metadata differs from this immutable object")
    else:
        with metadata.open("x") as output:
            json.dump(expected, output)
            output.flush()
            os.fsync(output.fileno())
        with part.open("xb"):
            pass
    offset = part.stat().st_size
    if offset > args.size:
        raise ValueError("partial file exceeds declared object size")
    agent = Agent(args.agent)
    with part.open("ab") as output:
        while offset < args.size:
            length = min(args.range_bytes, args.size - offset)
            with agent.connect(args.service, "example/1") as stream:
                header(stream, {"operation": "range", **expected, "offset": offset, "length": length})
                stream.shutdown_write()
                response = header(stream)
                if response != {"ok": True, **expected, "offset": offset, "length": length}:
                    raise ValueError("range response differs from exact request")
                remaining = length
                while remaining:
                    data = stream.recv(min(65536, remaining))
                    if not data:
                        raise EOFError("range interrupted; run the same command to resume")
                    output.write(data)
                    remaining -= len(data)
                    offset += len(data)
                output.flush()
                os.fsync(output.fileno())
            print(json.dumps({"received": offset, "size": args.size}), flush=True)
    if digest(part) != args.sha256:
        raise ValueError("final SHA256 differs; retain partial for diagnosis, do not publish")
    # Link refuses an existing target, then remove the private progress names.
    os.link(part, target)
    part.unlink()
    metadata.unlink()
    print(json.dumps({"status": "Verified", "path": str(target), **expected}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent", required=True, help="absolute private companion directory")
    sub = parser.add_subparsers(dest="operation", required=True)
    server = sub.add_parser("serve")
    server.add_argument("--allow-principal", action="append", required=True)
    server.add_argument("--file", type=Path)
    server.set_defaults(run=serve)
    event = sub.add_parser("echo")
    event.add_argument("--service", required=True)
    event.add_argument("message")
    event.set_defaults(run=echo)
    get = sub.add_parser("download")
    get.add_argument("--service", required=True)
    get.add_argument("--sha256", required=True)
    get.add_argument("--size", required=True, type=int)
    get.add_argument("--range-bytes", type=int, default=32 * 1024 * 1024)
    get.add_argument("--output", required=True, type=Path)
    get.set_defaults(run=download)
    args = parser.parse_args()
    args.run(args)


if __name__ == "__main__":
    main()
