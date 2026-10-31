# SPDX-License-Identifier: MIT
"""Typed checks preserve correlation, original caller time, and known closure."""
import tempfile
import socket
import time
import unittest
from unittest.mock import patch

from hypernet_streams import Agent, AgentError, Stream, Disposition, CompanionStatus
from hypernet_streams.context import boot_ms


class ContextTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.agent = Agent(self.directory.name, version=2)
        self.left, self.right = socket.socketpair()
        self.connection = Stream(self.left, {"network": "01"*32, "incarnation": "02"*32, "session": "03"*32, "generation": 4}, "04"*32)
        self.connection._state_lock = self.agent._state_lock
        self.agent._streams[self.connection.id] = self.connection
        self.responses = []

    def tearDown(self):
        self.connection.close()
        self.right.close()
        for stream in self.responses:
            stream.close()
        self.directory.cleanup()

    def response(self, action, *, timeout, disposition="permitted", delay=0, mutate=None, **fields):
        self.assertEqual(action, "checkAuthority")
        now = boot_ms()
        authority = None
        if disposition in ("permitted", "denied"):
            authority = {"network": "01"*32, "incarnation": "02"*32, "configuration": "05"*32, "epoch": 1, "height": 9, "state": "06"*32, "statementDigest": "07"*32, "evaluatedAtMs": 1000, "expiresAtMs": 2000, "code": 0 if disposition == "permitted" else 17}
        value = {"version": 2, "ok": True, **fields, "result": {"disposition": disposition, "callerStartedBootMs": now, "callerDeadlineBootMs": now+int(timeout*1000), "notAfterBootMs": now+int(timeout*1000), "authority": authority, "session": "03"*32, "generation": 4, "companionInstance": "08"*32, "endpointInstance": "09"*32, "controlGeneration": 1, "kernelBoot": "00112233-4455-6677-8899-aabbccddeeff", "privacy": {"direction": "incoming", "relayPath": "unknown"}}}
        if mutate:
            mutate(value)
        if delay:
            time.sleep(delay)
        left, right = socket.socketpair()
        self.responses.append(right)
        return value, left

    def test_denial_and_availability_are_typed_without_reading_messages(self):
        for disposition in Disposition:
            with self.subTest(disposition=disposition), patch.object(self.agent, "_request", side_effect=lambda *a, **kw: self.response(*a, disposition=disposition.value, **kw)):
                result = self.agent.check_authority(self.connection, b"a"*32)
                self.assertIs(result.disposition, disposition)
                self.assertEqual(result.certified, disposition in (Disposition.PERMITTED, Disposition.DENIED))
                self.assertEqual(result.permitted, disposition is Disposition.PERMITTED)
                self.assertEqual(result.action_digest, (b"a"*32).hex())
                self.assertEqual(len(result.nonce), 64)

    def test_a_new_check_and_known_close_invalidate_previous_observations(self):
        with patch.object(self.agent, "_request", side_effect=self.response):
            first = self.agent.check_authority(self.connection, b"a"*32)
            self.assertTrue(first.permitted)
            second = self.agent.check_authority(self.connection, b"b"*32)
            self.assertFalse(first.permitted)
            self.assertTrue(second.permitted)
            self.agent._observe_control(("08"*32, "09"*32, 2))
            self.assertFalse(second.permitted)
            third = self.agent.check_authority(self.connection, b"c"*32)
            self.connection.close()
            self.assertFalse(third.permitted)
        with self.assertRaises(AgentError) as error:
            self.agent.check_authority(self.connection, b"a"*32)
        self.assertEqual(error.exception.code, "NotActive")

    def test_observed_cancellation_or_new_control_during_check_is_not_overwritten(self):
        def cancelled(*args, **kwargs):
            self.connection._authority_epoch += 1  # Successful cancel observed while IPC was in flight.
            return self.response(*args, **kwargs)
        with patch.object(self.agent, "_request", side_effect=cancelled):
            result = self.agent.check_authority(self.connection, b"a"*32)
        self.assertIs(result.disposition, Disposition.NOT_ACTIVE)
        self.assertIs(result.receipt_disposition, Disposition.PERMITTED)
        self.assertFalse(result.permitted)

        later = ("08"*32, "09"*32, 2)
        def replaced(*args, **kwargs):
            self.agent._observe_control(later)
            return self.response(*args, **kwargs)  # Old generation1 receipt arrives after status saw2.
        with patch.object(self.agent, "_request", side_effect=replaced):
            result = self.agent.check_authority(self.connection, b"b"*32)
        self.assertFalse(result.permitted)
        self.assertEqual(self.agent._control, later)

    def test_delayed_ipc_consumes_original_sdk_deadline(self):
        def delayed(*args, **kwargs):
            # The companion begins later; its new relative lifetime cannot extend the SDK caller's.
            time.sleep(0.12)
            return self.response(*args, **kwargs)
        with patch.object(self.agent, "_request", side_effect=delayed):
            result = self.agent.check_authority(self.connection, b"a"*32, timeout=0.1)
        self.assertIs(result.disposition, Disposition.EXPIRED)
        self.assertIs(result.receipt_disposition, Disposition.PERMITTED)
        self.assertLess(result.usable_until_boot_ms, result.receipt_not_after_boot_ms)
        self.assertFalse(result.permitted)

    def test_correlation_session_deadline_and_certification_are_not_substitutable(self):
        mutations = [lambda r: r.update(nonce="aa"*32), lambda r: r.update(actionDigest="bb"*32), lambda r: r["result"].update(session="cc"*32), lambda r: r["result"].update(generation=5), lambda r: r["result"].update(authority=None), lambda r: r["result"].update(notAfterBootMs=r["result"]["callerDeadlineBootMs"]+1), lambda r: r["result"]["authority"].update(code=1), lambda r: r["result"]["authority"].update(network="dd"*32)]
        for mutate in mutations:
            with self.subTest(mutate=mutate), patch.object(self.agent, "_request", side_effect=lambda *a, **kw: self.response(*a, mutate=mutate, **kw)), self.assertRaises(AgentError) as error:
                self.agent.check_authority(self.connection, b"a"*32)
            self.assertEqual(error.exception.code, "Protocol")

    def test_status_separates_api_readiness_and_session_capability(self):
        value = {"capabilities": {"checkAuthority": {"supported": True, "capability": "checkAuthority-v2", "endpointReady": True, "companionInstance": "08"*32, "endpointInstance": "09"*32, "controlGeneration": 1}}, "connections": [{"id": self.connection.id, "direction": "outgoing", "checkAuthority": False, "privacy": {"relayPath": "nestedTlsViaRelay"}}]}
        status = CompanionStatus.parse(value)
        self.assertTrue(status.check_authority.supported)
        self.assertTrue(status.check_authority.endpoint_ready)
        self.assertFalse(status.connections[0].check_authority)
        value["capabilities"]["checkAuthority"]["endpointInstance"] = None
        with self.assertRaises(ValueError):
            CompanionStatus.parse(value)

    def test_control_transport_loss_is_not_a_certified_denial(self):
        for failure in (ConnectionResetError(), AgentError("Closed", "uninterpreted text")):
            with patch.object(self.agent, "_request", side_effect=failure):
                result = self.agent.check_authority(self.connection, b"a"*32)
            self.assertIs(result.disposition, Disposition.UNAVAILABLE)
            self.assertFalse(result.certified)
            self.assertIsNone(result.receipt_disposition)

    def test_v1_is_explicitly_unchanged(self):
        agent = Agent(self.directory.name)
        self.assertEqual(agent.version, 1)
        with self.assertRaises(AgentError) as error:
            agent.check_authority(self.connection, b"a"*32)
        self.assertEqual(error.exception.code, "UnsupportedVersion")


if __name__ == "__main__":
    unittest.main()
