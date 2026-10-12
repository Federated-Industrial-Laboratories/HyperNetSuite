#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read one retained form against an independently accepted local intake record."""
import argparse
import json
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--suite', type=Path, required=True)
    for name in ('bootstrap', 'bootstrap-digest', 'directory', 'clock-witness',
                 'mail-directory', 'vault', 'age-key', 'mailbox', 'message'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--clock-monitor-key')
    parser.add_argument('--host-kernel-boot')
    args = parser.parse_args()
    if bool(args.clock_monitor_key) != bool(args.host_kernel_boot):
        parser.error('Both clock monitor pins are required together')
    command = [str(args.suite.resolve(strict=True)), 'forms', 'receive-local']
    for name, value in vars(args).items():
        if name != 'suite' and value is not None:
            command.extend(['--' + name.replace('_', '-'), str(value)])
    result = subprocess.run(command, check=True, capture_output=True, timeout=180)
    if len(result.stdout) > 65536:
        raise ValueError('Form response exceeds its bound')
    value = json.loads(result.stdout)
    if value.get('status') not in ('Accepted', 'Unrecognised'):
        raise ValueError('Unexpected form response')
    # ASCII JSON preserves controls as escapes when output is displayed in a terminal.
    print(json.dumps(value, ensure_ascii=True, separators=(',', ':')))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        text = ('Form intake failed: ' + str(error)).encode('unicode_escape').decode('ascii')
        print(text, file=sys.stderr)
        sys.exit(1)
