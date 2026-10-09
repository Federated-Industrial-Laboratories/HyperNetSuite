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
import unittest

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / 'Tools/Bundle.py'
BINARY = None


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
        cls.call('Create', '--binary', str(BINARY), '--output', str(cls.archive), '--signing-key', str(cls.key))
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
        self.call('Install', '--archive', str(self.archive), '--signature', str(self.archive) + '.sig',
                  '--public-key', str(self.key) + '.pub', '--prefix', str(self.prefix()))

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


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True)
    parser.add_argument('tests', nargs='*', help='Optional unittest case names')
    args = parser.parse_args()
    BINARY = Path(args.binary).resolve(strict=True)
    unittest.main(argv=[sys.argv[0], *args.tests], verbosity=2)
