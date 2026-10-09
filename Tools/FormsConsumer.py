#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Read one authenticated form with an independently enrolled receiving device.
import argparse
import json
import subprocess
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--suite', type=Path, required=True)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--vault', type=Path, required=True)
    parser.add_argument('--key', type=Path, required=True)
    parser.add_argument('--mailbox', required=True)
    parser.add_argument('--message-id', required=True)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--host')
    source.add_argument('--local', action='store_true')
    args = parser.parse_args()
    command = [str(args.suite.resolve(strict=True)), '--config', str(args.config),
               'forms', '--vault', str(args.vault), '--key', str(args.key),
               'receive', '--mailbox', args.mailbox, '--message-id', args.message_id]
    command += ['--local'] if args.local else ['--host', args.host]
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
        print(f'Form intake failed: {error}', file=sys.stderr)
        sys.exit(1)
