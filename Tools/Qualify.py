#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Qualify an independently verified installed client without network access."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys
import tempfile


def run(arguments, timeout=45):
    result = subprocess.run(arguments, stdin=subprocess.DEVNULL, capture_output=True,
                            timeout=timeout, env={**os.environ, 'LC_ALL': 'C'})
    if result.returncode != 0 or len(result.stdout) + len(result.stderr) > 1024 * 1024:
        raise ValueError('Qualification command failed: ' + Path(arguments[0]).name)
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prefix', required=True)
    parser.add_argument('--public-key', required=True, help='Independently pinned package signer')
    parser.add_argument('--ssh-keygen', default='/usr/bin/ssh-keygen')
    args = parser.parse_args()
    prefix = Path(args.prefix).absolute()
    # This command and its verifier must come from an independently trusted source.
    verifier = Path(__file__).with_name('Bundle.py')
    manifest = json.loads(run([sys.executable, str(verifier), '--ssh-keygen', args.ssh_keygen,
                              'VerifyInstalled', '--prefix', str(prefix), '--public-key', args.public_key]))
    binary = prefix / 'Bin/HyperNetSuite'
    report = {'product': 'HyperNetSuite', 'version': manifest['version'],
              'binarySha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
              'architecture': platform.machine(), 'kernel': platform.release(),
              'distribution': platform.freedesktop_os_release().get('PRETTY_NAME', 'Unknown'),
              'python': platform.python_version(), 'libc': list(platform.libc_ver()),
              'elf': manifest['metadata'], 'networkUsed': False, 'checks': []}
    version = run([str(binary), '--version']).decode('ascii').strip()
    if version != 'HyperNetSuite ' + manifest['version']:
        raise ValueError('Installed binary and package versions differ')
    report['checks'].append('Exact binary version')
    with tempfile.TemporaryDirectory(prefix='HyperNetSuiteQualification') as directory:
        private = Path(directory)
        key = private / 'Identity.json'
        generated = json.loads(run([str(binary), 'keygen', '--output', str(key)]))
        if not re.fullmatch(r'[a-f0-9]{64}', generated['publicKey']) or stat.S_IMODE(key.stat().st_mode) != 0o600:
            raise ValueError('Private identity generation failed')
        original = key.read_bytes()
        duplicate = subprocess.run([str(binary), 'keygen', '--output', str(key)], capture_output=True, timeout=10)
        if duplicate.returncode == 0 or key.read_bytes() != original:
            raise ValueError('Identity overwrite protection failed')
        report['checks'].append('Private identity generation and overwrite refusal')
        page = private / 'Page.txt'
        page.write_text('HyperNetPage/1\n# Qualification\n: Safe plain text.\n=> https://example.com/ Inert reference\n')
        preview = run([str(binary), 'pages', 'preview', str(page), '--ascii'])
        if b'UNAPPROVED' not in preview or b'Safe plain text.' not in preview or any(byte < 32 and byte != 10 or byte == 127 for byte in preview):
            raise ValueError('Plain preview output failed')
        report['checks'].append('Safe plain preview and inert link')
        run([sys.executable, str(prefix / 'Tests/ReaderTerminal.py'), str(binary)], timeout=90)
        report['checks'].append('Reader pseudoterminal resize, signals and restoration')
        report['markup'] = json.loads(run([sys.executable, str(prefix / 'Tests/MarkupRobustness.py'), str(binary)], timeout=90))
        report['checks'].append('Bounded markup rejection and output safety')
    report['status'] = 'Passed'
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print('HyperNetSuite qualification: ' + str(error).encode('ascii', 'backslashreplace').decode(), file=sys.stderr)
        sys.exit(1)
