#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise signed package trust, bounded archives and private installation lifecycle."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
import zipfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / 'Tools/Bundle.py'
BINARY = None
SDK_WHEEL = None
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'Tools'))
import Bundle
import PackageTrust


class BundleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='HyperNetSuiteBundleTests')
        cls.root = Path(cls.temporary.name)
        cls.key = cls.root / 'Signer'
        cls.other = cls.root / 'OtherSigner'
        for key in (cls.key, cls.other):
            subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)], check=True)
        cls.archive = cls.root / 'Suite.tar'
        cls.call('Create', '--binary', str(BINARY), '--streams-sdk-wheel', str(SDK_WHEEL), '--output', str(cls.archive), '--signing-key', str(cls.key))
        cls.policy = cls.root / 'Target.json'
        cls.call('Authorise', '--archive', str(cls.archive), '--signature', str(cls.archive) + '.sig',
                 '--public-key', str(cls.key) + '.pub', '--signing-key', str(cls.key),
                 '--output', str(cls.policy), '--version-floor', '0.8.0',
                 '--state-contract', 'HyperNet080Client1', '--root-generation', '1',
                 '--sequence', '1', '--not-before', str(int(time.time()) - 1),
                 '--expires', str(int(time.time()) + 3600))
        with tarfile.open(cls.archive) as archive:
            cls.entries = [(item, archive.extractfile(item).read()) for item in archive.getmembers()]

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    @classmethod
    def call(cls, *args, success=True):
        result = subprocess.run([sys.executable, str(BUNDLE), *args], capture_output=True, timeout=180)
        if success and result.returncode != 0:
            raise AssertionError(result.stderr.decode())
        if not success and result.returncode == 0:
            raise AssertionError('Invalid package operation succeeded')
        return result

    def prefix(self):
        return self.root / self._testMethodName

    def verify(self, archive=None, key=None, success=True):
        archive = archive or self.archive
        return self.call('Verify', '--archive', str(archive), '--signature', str(archive) + '.sig',
                         '--public-key', str(key or self.key) + '.pub', success=success)

    def install(self):
        trust = self.prefix().with_name(self.prefix().name + 'Trust')
        self.call('TrustInit', '--trust-directory', str(trust), '--public-key', str(self.key) + '.pub',
                  '--root-pin', PackageTrust.pin(Bundle.public_key(str(self.key) + '.pub')),
                  '--root-generation', '1', '--version-floor', '0.8.0', '--state-contract', 'HyperNet080Client1')
        self.call('Install', '--archive', str(self.archive), '--signature', str(self.archive) + '.sig',
                  '--public-key', str(self.key) + '.pub', '--prefix', str(self.prefix()),
                  '--trust-directory', str(trust), '--policy', str(self.policy),
                  '--policy-signature', str(self.policy) + '.sig')

    def lifecycle(self, command, success=True):
        return self.call(command, '--prefix', str(self.prefix()), '--public-key', str(self.key) + '.pub', success=success)

    def modified_archive(self, mutate, namespace='HyperNetSuiteBundle1'):
        path = self.prefix().with_suffix('.tar')
        with tarfile.open(path, 'w', format=tarfile.USTAR_FORMAT) as archive:
            for index, (original, payload) in enumerate(self.entries):
                item = tarfile.TarInfo(original.name)
                item.mode, item.size = original.mode, len(payload)
                item, payload = mutate(index, item, payload)
                archive.addfile(item, io.BytesIO(payload) if item.isreg() else None)
        subprocess.run(['ssh-keygen', '-Y', 'sign', '-n', namespace, '-f', str(self.key), str(path)], capture_output=True, check=True)
        return path

    def test_signature_and_exact_manifest(self):
        manifest = json.loads(self.verify().stdout)
        self.assertEqual(manifest['product'], 'HyperNetSuite')
        self.assertEqual(manifest['metadata']['binarySha256'], hashlib.sha256(BINARY.read_bytes()).hexdigest())

    def test_context_sdk_module_is_packaged_and_source_bound(self):
        paths = {item.name for item, _ in self.entries}
        self.assertIn('Payload/SDK/hypernet_streams/context.py', paths)
        self.assertIn('Payload/Examples/ApplicationStreams/authority_service.py', paths)
        modified = self.prefix()
        modified.mkdir()
        wheel = modified / SDK_WHEEL.name
        with zipfile.ZipFile(SDK_WHEEL) as source, zipfile.ZipFile(wheel, 'w') as destination:
            for item in source.infolist():
                payload = source.read(item)
                if item.filename == 'hypernet_streams/context.py':
                    payload += b'\n# changed implementation\n'
                destination.writestr(item, payload)
        with self.assertRaises(ValueError):
            Bundle.stream_wheel(wheel, ROOT)

    def test_wrong_pinned_signer(self):
        self.verify(key=self.other, success=False)

    def test_wrong_namespace(self):
        path = self.modified_archive(lambda i, item, data: (item, data), 'HyperNetBundle1')
        self.verify(path, success=False)

    def test_tampered_unsigned_bytes(self):
        path = self.prefix().with_suffix('.tar')
        data = bytearray(self.archive.read_bytes())
        data[700] ^= 1
        path.write_bytes(data)
        shutil.copyfile(str(self.archive) + '.sig', str(path) + '.sig')
        self.verify(path, success=False)

    def test_signed_traversal(self):
        def mutate(index, item, data):
            if index == 1:
                item.name = 'Payload/../Outside'
            return item, data
        self.verify(self.modified_archive(mutate), success=False)
        self.assertFalse((self.root / 'Outside').exists())

    def test_signed_symbolic_member(self):
        def mutate(index, item, data):
            if index == 1:
                item.type, item.linkname, item.size = tarfile.SYMTYPE, '/tmp/Outside', 0
            return item, data
        self.verify(self.modified_archive(mutate), success=False)

    def test_signed_inventory_digest_mismatch(self):
        def mutate(index, item, data):
            if index == 1:
                data = b'x' * len(data)
            return item, data
        self.verify(self.modified_archive(mutate), success=False)

    def test_signed_duplicate_member(self):
        first = self.entries[1][0].name
        def mutate(index, item, data):
            if index == 2:
                item.name = first
            return item, data
        self.verify(self.modified_archive(mutate), success=False)

    def test_archive_symlink_or_fifo(self):
        path = self.prefix()
        path.symlink_to(self.archive)
        self.call('Verify', '--archive', str(path), '--signature', str(self.archive) + '.sig', '--public-key', str(self.key) + '.pub', success=False)
        path.unlink()
        os.mkfifo(path)
        self.call('Verify', '--archive', str(path), '--signature', str(self.archive) + '.sig', '--public-key', str(self.key) + '.pub', success=False)
        path.unlink()

    def test_install_verify_remove_preserves_external_identity(self):
        profile = self.root / 'PersonalIdentity.json'
        profile.write_text('External private state')
        self.install()
        self.lifecycle('VerifyInstalled')
        self.assertEqual(self.prefix().stat().st_mode & 0o777, 0o700)
        self.lifecycle('Remove')
        self.assertFalse(self.prefix().exists())
        self.assertEqual(profile.read_text(), 'External private state')
        profile.unlink()

    def test_retained_package_directory_cannot_redirect(self):
        self.install()
        retained = self.prefix() / 'Package'
        outside = self.root / 'RedirectedPackage'
        retained.rename(outside)
        retained.symlink_to(outside, target_is_directory=True)
        self.lifecycle('VerifyInstalled', success=False)
        self.lifecycle('Remove', success=False)
        self.assertTrue((outside / 'Archive.tar').is_file())
        retained.unlink()
        outside.rename(retained)
        self.lifecycle('Remove')

    def test_existing_prefix_refused(self):
        self.prefix().mkdir()
        self.call('Install', '--archive', str(self.archive), '--signature', str(self.archive) + '.sig',
                  '--public-key', str(self.key) + '.pub', '--prefix', str(self.prefix()), success=False)
        self.assertEqual(list(self.prefix().iterdir()), [])

    def test_interrupted_publication_retains_floor_and_exact_retry_succeeds(self):
        trust = self.prefix().with_name(self.prefix().name + 'Trust')
        self.call('TrustInit', '--trust-directory', str(trust), '--public-key', str(self.key) + '.pub',
                  '--root-pin', PackageTrust.pin(Bundle.public_key(str(self.key) + '.pub')),
                  '--root-generation', '1', '--version-floor', '0.8.0', '--state-contract', 'HyperNet080Client1')
        args = argparse.Namespace(archive=self.archive, signature=str(self.archive) + '.sig',
            public_key=str(self.key) + '.pub', prefix=self.prefix(), trust_directory=trust,
            policy=self.policy, policy_signature=str(self.policy) + '.sig', ssh_keygen='/usr/bin/ssh-keygen')
        with patch.object(Bundle, 'rename_new', side_effect=OSError('Interrupted publication')):
            with self.assertRaises(OSError):
                Bundle.install(args)
        self.assertFalse(self.prefix().exists())
        self.assertEqual(json.loads((trust / 'Trust.json').read_bytes())['sequence'], 1)
        previous_umask = os.umask(0o022)
        try:
            Bundle.install(args)
        finally:
            os.umask(previous_umask)
        self.lifecycle('VerifyInstalled')
        self.lifecycle('Remove')

    def test_modified_inventory_refuses_removal(self):
        self.install()
        binary = self.prefix() / 'Bin/HyperNetSuite'
        original = binary.read_bytes()
        binary.write_bytes(b'Modified')
        self.lifecycle('VerifyInstalled', success=False)
        self.lifecycle('Remove', success=False)
        self.assertTrue((self.prefix() / 'Manifest.json').exists())
        binary.write_bytes(original)
        self.lifecycle('Remove')

    def test_unexpected_entries_refuse_removal(self):
        self.install()
        extra = self.prefix() / 'PrivateData'
        extra.mkdir()
        self.lifecycle('Remove', success=False)
        extra.rmdir()
        extra.write_text('Must not remove')
        self.lifecycle('Remove', success=False)
        self.assertEqual(extra.read_text(), 'Must not remove')
        extra.unlink()
        extra.symlink_to(self.root / 'Outside')
        self.lifecycle('Remove', success=False)
        extra.unlink()
        self.lifecycle('Remove')


class OfflineUpdates(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='PackageUpdateTests')
        self.root = Path(self.temporary.name)
        self.key, self.other = self.root / 'Signer', self.root / 'NextSigner'
        for key in (self.key, self.other):
            subprocess.run(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)], check=True)
        self.trust = self.root / 'Trust'
        self.contract = PackageTrust.CONTRACTS[Bundle.PRODUCT]
        self.init = argparse.Namespace(command='TrustInit', trust_directory=self.trust,
            public_key=str(self.key) + '.pub', root_pin=PackageTrust.pin(Bundle.public_key(str(self.key) + '.pub')),
            root_generation=1, version_floor='0.8.0', state_contract=self.contract)
        PackageTrust.trust_command(Bundle, self.init)
        self.archive = self.root / 'Archive.tar'
        self.archive.write_bytes(b'Exact synthetic archive identity')
        self.manifest = {'version': '0.8.0', 'architecture': Bundle.architecture(),
                         'files': [{'path': 'Tools/PackageTrust.py'}]}
        self.original = Bundle.encode(self.manifest)
        self.now = int(time.time())
        self.target = {'format': 1, 'product': Bundle.PRODUCT, 'architecture': Bundle.architecture(),
            'version': '0.8.0', 'versionFloor': '0.8.0', 'stateContract': self.contract,
            'rootGeneration': 1, 'rootPin': self.init.root_pin, 'sequence': 1,
            'notBefore': self.now - 1, 'expires': self.now + 60,
            'archiveSha256': Bundle.digest_file(self.archive), 'archiveBytes': self.archive.stat().st_size,
            'manifestSha256': hashlib.sha256(self.original).hexdigest()}
        self.serial = 0

    def tearDown(self):
        self.temporary.cleanup()

    def policy(self, changes=None, key=None):
        self.serial += 1
        policy = self.root / ('Target' + str(self.serial) + '.json')
        policy.write_bytes(Bundle.encode(dict(self.target, **(changes or {}))))
        subprocess.run(['/usr/bin/ssh-keygen', '-Y', 'sign', '-n', Bundle.PRODUCT + 'Update1',
                        '-f', str(key or self.key), str(policy)], check=True, capture_output=True)
        return argparse.Namespace(trust_directory=self.trust, policy=policy,
            policy_signature=str(policy) + '.sig', public_key=str(key or self.key) + '.pub',
            ssh_keygen='/usr/bin/ssh-keygen')

    def accept(self, args, commit=True):
        with PackageTrust.Admission(Bundle, args) as admission:
            with tempfile.TemporaryDirectory(dir=self.root) as scratch:
                admission.check(self.archive, self.manifest, self.original, Path(scratch))
                if commit:
                    admission.commit()
                return admission.target_digest

    def state(self):
        return json.loads((self.trust / 'Trust.json').read_bytes())

    def test_update_floor_exact_retry_equivocation_and_rollback(self):
        first = self.policy()
        self.accept(first)
        self.assertEqual(self.accept(first), self.state()['targetDigest'])
        with self.assertRaisesRegex(ValueError, 'conflicts'):
            self.accept(self.policy({'expires': self.now + 61}))
        self.accept(self.policy({'sequence': 2}))
        with self.assertRaisesRegex(ValueError, 'below the retained floor'):
            self.accept(first)
        self.assertEqual(self.state()['sequence'], 2)

    def test_update_expiry_scope_contract_and_numeric_bounds_fail_closed(self):
        for changes in ({'expires': self.now}, {'notBefore': self.now + 30},
                        {'rootGeneration': 2}, {'rootPin': '0' * 64},
                        {'stateContract': 'Other'}, {'product': 'Other'},
                        {'architecture': 'Other'}, {'sequence': True},
                        {'sequence': 1 << 63}, {'archiveBytes': True},
                        {'versionFloor': '0.8.1'}, {'archiveSha256': '0' * 64}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.accept(self.policy(changes))
        self.assertEqual(self.state()['sequence'], 0)
        self.assertIsNone(self.state()['targetDigest'])

    def test_update_rechecks_expiry_at_floor_and_publication_boundaries(self):
        args = self.policy()
        with PackageTrust.Admission(Bundle, args) as admission:
            with tempfile.TemporaryDirectory(dir=self.root) as scratch:
                admission.check(self.archive, self.manifest, self.original, Path(scratch))
            with patch.object(PackageTrust.time, 'time', return_value=self.now + 60):
                with self.assertRaisesRegex(ValueError, 'not currently valid'):
                    admission.commit()
            self.assertEqual(self.state()['sequence'], 0)
            admission.commit()
            with patch.object(PackageTrust.time, 'time', return_value=self.now + 60):
                with self.assertRaisesRegex(ValueError, 'not currently valid'):
                    admission.fresh()
        self.assertEqual(self.state()['sequence'], 1)

    def test_update_root_rotation_preserves_floor_and_requires_new_sequence(self):
        self.accept(self.policy())
        before = self.state()
        args = argparse.Namespace(command='TrustRotate', trust_directory=self.trust,
            expected_trust_digest=PackageTrust.digest(Bundle, before), public_key=str(self.other) + '.pub',
            root_pin=PackageTrust.pin(Bundle.public_key(str(self.other) + '.pub')), root_generation=2)
        with patch.object(args, 'root_pin', '0' * 64), self.assertRaises(ValueError):
            PackageTrust.trust_command(Bundle, args)
        PackageTrust.trust_command(Bundle, args)
        self.assertEqual(self.state()['sequence'], before['sequence'])
        self.assertEqual(self.state()['targetDigest'], before['targetDigest'])
        self.assertEqual(self.state()['versionFloor'], before['versionFloor'])
        with self.assertRaisesRegex(ValueError, 'changed since inspection'):
            PackageTrust.trust_command(Bundle, args)
        with self.assertRaisesRegex(ValueError, 'differs from retained'):
            self.accept(self.policy())
        changes = {'rootGeneration': 2, 'rootPin': args.root_pin}
        with self.assertRaisesRegex(ValueError, 'conflicts'):
            self.accept(self.policy(changes, self.other))
        self.accept(self.policy(dict(changes, sequence=2), self.other))

    def test_update_lock_clock_floor_and_missing_policy_refuse(self):
        args = self.policy()
        with PackageTrust.locked(Bundle, self.trust), self.assertRaises(BlockingIOError):
            self.accept(args)
        with patch.object(PackageTrust.time, 'time', return_value=self.state()['lastTime'] - 1):
            with self.assertRaisesRegex(ValueError, 'clock moved'):
                self.accept(args)
        with self.assertRaisesRegex(ValueError, 'requires retained trust'):
            PackageTrust.Admission(Bundle, argparse.Namespace())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--streams-sdk-wheel', required=True)
    parser.add_argument('tests', nargs='*', help='Optional unittest case names')
    args = parser.parse_args()
    BINARY = Path(args.binary).resolve(strict=True)
    SDK_WHEEL = Path(args.streams_sdk_wheel).resolve(strict=True)
    unittest.main(argv=[sys.argv[0], *args.tests], verbosity=2)
