# SPDX-License-Identifier: MIT
"""The local wire boundary separates verified context from raw stream bytes."""
import json
import os
from pathlib import Path
import socket
import struct
import tempfile
import threading
import unittest

from hypernet_streams import Agent, AgentError


class IpcTests(unittest.TestCase):
    def test_context_is_separate_and_half_close_retains_response(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            path = directory / "Control.sock"
            listener.bind(str(path))
            path.chmod(0o600)
            listener.listen(1)
            errors = []

            def serve():
                try:
                    connection, _ = listener.accept()
                    with connection:
                        size = struct.unpack("!I", connection.recv(4))[0]
                        request = json.loads(connection.recv(size))
                        self.assertEqual(request["action"], "connect")
                        self.assertEqual(request["service"], "named-service")
                        response = json.dumps({"version": 1, "ok": True, "id": "finite-id", "peer": {"principal": "verified-caller"}}).encode()
                        connection.sendall(struct.pack("!I", len(response)) + response)
                        self.assertEqual(connection.recv(8), b"request")
                        self.assertEqual(connection.recv(1), b"")
                        connection.sendall(b"response")
                except BaseException as error:
                    errors.append(error)

            worker = threading.Thread(target=serve)
            worker.start()
            with Agent(directory).connect("named-service", "example/1") as stream:
                self.assertEqual(stream.peer["principal"], "verified-caller")
                stream.sendall(b"request")
                stream.shutdown_write()
                self.assertEqual(stream.recv(8), b"response")
            worker.join(5)
            listener.close()
            self.assertFalse(worker.is_alive())
            if errors:
                raise errors[0]

    def test_socket_and_directory_modes_fail_closed(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            path = directory / "Control.sock"
            listener.bind(str(path))
            path.chmod(0o660)
            listener.listen(1)
            with self.assertRaises(AgentError):
                Agent(directory).status()
            listener.close()
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            directory.chmod(0o750)
            with self.assertRaises(AgentError):
                Agent(directory).status()
            directory.chmod(0o700)

    def test_oversized_response_refuses_without_reading_a_payload(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            path = directory / "Control.sock"
            listener.bind(str(path))
            path.chmod(0o600)
            listener.listen(1)

            def serve():
                connection, _ = listener.accept()
                with connection:
                    size = struct.unpack("!I", connection.recv(4))[0]
                    connection.recv(size)
                    connection.sendall(struct.pack("!I", 16385))

            worker = threading.Thread(target=serve)
            worker.start()
            with self.assertRaises(AgentError) as refused:
                Agent(directory).status()
            self.assertEqual(refused.exception.code, "Frame")
            worker.join(5)
            listener.close()
            self.assertFalse(worker.is_alive())


if __name__ == "__main__":
    unittest.main()
