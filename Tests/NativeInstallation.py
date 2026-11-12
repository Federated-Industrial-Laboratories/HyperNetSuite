#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check the authenticated bootstrap boundary with real signed inert packages."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'Tools'))
import Bundle
import PackageTrust


class Bootstrap(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='HyperNetBootstrapTest')
        self.root = Path(self.temporary.name)
        result = subprocess.run([sys.executable, '-B', str(ROOT / 'Tests/NativeInstallationFixture.py'), str(self.root)], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode('utf-8', 'replace'))
        self.pin = json.loads(result.stdout)['rootPin']
        self.directory = self.root / 'Installation'
        self.options = argparse.Namespace(release_directory=str(self.root / 'Packages'), directory=str(self.directory), ssh_keygen='/usr/bin/ssh-keygen')
        self.original_run = Bundle.run
        self.launched = []

    def tearDown(self):
        self.temporary.cleanup()

    def launch(self, args, **kwargs):
        if Path(args[0]).name == 'HyperNetSuite':
            executable = Path(args[0])
            self.assertEqual(executable.parent.parent.parent, self.directory / 'Products/Suite/Installed')
            self.assertEqual(executable.stat().st_mode & 0o777, 0o755)
            self.assertEqual(executable.parent.parent.stat().st_mode & 0o777, 0o700)
            self.assertEqual(args[1:], ['native-installation', 'install', '--release-directory', str(self.root / 'Packages'), '--directory', str(self.directory), '--json'])
            self.launched.append(executable)
            return json.dumps({'format': 'HyperNetNativeInstallation/1', 'status': 'Ready', 'suiteExecutable': str(executable)}).encode()
        return self.original_run(args, **kwargs)

    def test_bootstrap_authenticates_one_final_prefix_and_refuses_changed_binary(self):
        with patch.object(Bundle, 'run', side_effect=self.launch):
            with self.assertRaisesRegex(ValueError, 'pinned release key'):
                Bundle.bootstrap(self.options)
            self.assertEqual(self.launched, [])
            with patch.object(Bundle, 'PUBLISHER_PIN', self.pin):
                first = Bundle.bootstrap(self.options)
                self.assertEqual(first, Bundle.bootstrap(self.options))
                self.assertEqual(len(list((self.directory / 'Products/Suite/Installed').iterdir())), 1)
                executable = Path(first['suiteExecutable'])
                executable.write_bytes(b'Changed')
                with self.assertRaisesRegex(ValueError, 'modified'):
                    Bundle.bootstrap(self.options)
                self.assertEqual(len(self.launched), 2)

    def test_historical_target_verification_does_not_authorise_bootstrap(self):
        with patch.object(Bundle, 'run', side_effect=self.launch), patch.object(Bundle, 'PUBLISHER_PIN', self.pin):
            installed = Bundle.bootstrap(self.options)
            target = next((self.directory / 'Products/Suite/Targets').iterdir())
            selected = argparse.Namespace(prefix=str(Path(installed['suiteExecutable']).parent.parent),
                public_key=str(target / 'Publisher.pub'), policy=str(target / 'Target.json'),
                policy_signature=str(target / 'Target.json.sig'), ssh_keygen='/usr/bin/ssh-keygen')
            with patch.object(PackageTrust.time, 'time', return_value=int(time.time()) + 7200):
                historical = Bundle.inspect_installed_target(selected)
                self.assertFalse(historical['activationAllowed'])
                self.assertEqual(historical['targetDigest'], target.name)
                with self.assertRaisesRegex(ValueError, 'not currently valid'):
                    Bundle.bootstrap(self.options)
            self.assertEqual(len(self.launched), 1)

    def test_only_the_mapped_suite_executable_gains_execute_permission(self):
        self.assertEqual(Bundle.file_mode('Bin/HyperNetSuite'), 0o755)
        self.assertEqual(Bundle.file_mode('Bin/HyperNetSuite', '0.10.3'), 0o700)
        self.assertEqual(Bundle.file_mode('Tools/Bundle.py'), 0o700)
        self.assertEqual(Bundle.file_mode('ReadMe.md'), 0o600)


if __name__ == '__main__':
    unittest.main()
