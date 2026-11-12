#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check the authenticated bootstrap boundary with real signed inert packages."""
import argparse
import json
import os
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


class InstallerEntry(unittest.TestCase):
    """Exercise shell dispatch only; Bootstrap above covers signed package verification."""
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='HyperNetInstallerEntry')
        self.root = Path(self.temporary.name)
        self.release = self.root / 'Outer Release'
        for name in ['Tools', 'Packages/Core', 'Packages/Suite', 'Bin']:
            (self.release / name).mkdir(parents=True, mode=0o700, exist_ok=True)
        self.script = self.release / 'Tools/Install.sh'
        self.script.write_bytes((ROOT / 'Tools/Install.sh').read_bytes())
        self.executable = self.root / 'Verified Installed Suite/Bin/HyperNetSuite'
        self.executable.parent.mkdir(parents=True, mode=0o700)
        self.log = self.root / 'Invocations.jsonl'
        self.executable.write_text('#!/usr/bin/python3\nimport json,os,sys\n'
            'with open(os.environ["ENTRY_LOG"],"a") as f: f.write(json.dumps({"args":sys.argv[1:],"stdin":sys.stdin.read() if sys.argv[1:3]==["join","desktop"] else None})+"\\n")\n'
            'raise SystemExit(7 if sys.argv[1:]==["join","install"] and os.environ.get("ENTRY_HANDLER_FAIL")=="1" else 0)\n')
        self.executable.chmod(0o755)
        adjacent = self.release / 'Bin/HyperNetSuite'
        adjacent.write_text('#!/bin/sh\nexit 93\n')
        adjacent.chmod(0o755)
        self.bootstrap('Ready')

    def tearDown(self):
        self.temporary.cleanup()

    def bootstrap(self, status):
        result = {'format':'HyperNetNativeInstallation/1','status':status,'suiteExecutable':str(self.executable)}
        (self.release / 'Tools/Bundle.py').write_text('import json\nprint(json.dumps('+repr(result)+'))\n')

    def run_entry(self, handler_fail=False):
        return subprocess.run(['/bin/bash', str(self.script)], cwd=self.root, capture_output=True,
            env={**os.environ, 'ENTRY_LOG':str(self.log), 'ENTRY_HANDLER_FAIL':str(int(handler_fail))})

    def test_verified_installed_path_registers_links_then_opens_native_join(self):
        result = self.run_entry()
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        values = [json.loads(line) for line in self.log.read_text().splitlines()]
        self.assertEqual([v['args'] for v in values], [['join','install'],['join','desktop','--application','native']])
        self.assertEqual(json.loads(values[1]['stdin']), {'location':None})

    def test_link_registration_failure_preserves_direct_window_access(self):
        result = self.run_entry(handler_fail=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn(b'link registration needs repair', result.stderr)
        self.assertEqual(len(self.log.read_text().splitlines()), 2)

    def test_unconfirmed_installation_never_launches_a_window(self):
        self.bootstrap('Refused')
        result = self.run_entry()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.log.exists())


if __name__ == '__main__':
    unittest.main()
