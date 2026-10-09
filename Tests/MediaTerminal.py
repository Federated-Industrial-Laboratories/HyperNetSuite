#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check graphics wire bounds, explicit reveal, local motion and restoration in a PTY.

Input: HyperNetSuite executable. This is protocol evidence, not native terminal
visual qualification. All files and pseudo-terminal state are disposable.
"""
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pty
import re
import select
import struct
import subprocess
import sys
import tempfile
import termios
import time

FRAME = re.compile(rb'\x1b_Ga=T,t=d,f=24,s=(\d+),v=(\d+),i=(\d+),')


def main():
    binary = str(Path(sys.argv[1]).resolve())
    checks = []
    with tempfile.TemporaryDirectory(prefix='HyperNetMediaTerminal') as temporary:
        root = Path(temporary)
        rgb = bytes([255, 0, 0]) * 64 * 32
        asset = {'id': 'Picture', 'profile': 'HyperNetRaster/1', 'width': 64, 'height': 32,
            'bytes': len(rgb), 'digest': hashlib.sha256(rgb).hexdigest(), 'hosts': ['1' * 64], 'copies': 1}
        path = root / 'Picture.Rgb'
        path.write_bytes(rgb)
        page = root / 'Page.txt'
        page.write_text('HyperNetPage/2\n# Media\n@Asset ' + json.dumps(asset, separators=(',', ':')) + '\n'
            '@Text {"id":"Caption","value":"Visible text","motion":{"preset":"ColourPulse","durationMs":2000}}\n'
            '@ScrollBox {"id":"Window","label":"Image window","rows":5}\n'
            '@Image {"id":"PictureView","asset":"Picture","alt":"Red rectangle","rows":8,"motion":{"preset":"ImageFade","durationMs":2000}}\n'
            '@End\n@Button {"label":"Reveal","action":{"kind":"Reveal","target":"PictureView"}}\n')
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 24, 72, 576, 384))
        original = termios.tcgetattr(slave)
        env = dict(os.environ, TERM='xterm-kitty')
        for key in ['TMUX', 'STY', 'SSH_CONNECTION', 'NO_COLOR']:
            env.pop(key, None)
        process = subprocess.Popen([binary, 'pages', 'preview', str(page), '--tui', '--graphics', 'kitty',
            '--media', 'Picture=' + str(path)], stdin=slave, stdout=slave, stderr=slave, env=env, start_new_session=True)
        complete = bytearray()
        def read_for(seconds):
            result = bytearray()
            deadline = time.monotonic() + seconds
            while time.monotonic() < deadline:
                if select.select([master], [], [], min(.05, max(0, deadline-time.monotonic())))[0]:
                    try:
                        chunk = os.read(master, 262144)
                    except OSError:
                        break
                    result.extend(chunk)
            complete.extend(result)
            return bytes(result)
        try:
            initial = read_for(.4)
            assert b'Page content' in initial and b'Red rectangle' in initial
            assert not FRAME.search(initial)
            assert not read_for(.25), 'static reader repainted while idle'
            checks.append('Initial view is static and does not read or transmit image pixels')
            os.write(master, b'a')
            motion = read_for(.65)
            assert b'Local motion enabled' in motion and not FRAME.search(motion)
            assert motion.count(b'\x1b[2J') <= 8
            os.write(master, b'a')
            read_for(.2)
            checks.append('Unrevealed effects paint locally without retrieving pixels and obey the text cap')
            # The first control is the ScrollBox; the second is its explicit Reveal button.
            os.write(master, b'\t\t\r')
            revealed = read_for(.65)
            matches = FRAME.findall(revealed)
            assert matches, revealed[-1000:]
            assert all(int(width) <= 536 and int(height) <= 5 * 16 for width, height, _ in matches)
            assert not FRAME.search(read_for(.3)), 'static revealed image generated more frames'
            checks.append('Explicit reveal emits a clipped bounded image and then remains static')
            os.write(master, b'a')
            read_for(.65)
            os.write(master, b'a\t\x1b[B\x1b[B')
            scrolled = read_for(.75)
            assert FRAME.search(scrolled), 'image did not repaint after rapid pause/focus/scroll'
            assert b'row 3' in scrolled
            os.write(master, b'\x1b[H')
            read_for(.6)
            checks.append('Rapid pause, focus and scroll retain a deferred clipped image repaint')
            os.write(master, b'a')
            animated = read_for(2.35)
            count = len(FRAME.findall(animated))
            assert 1 <= count <= 5, count
            assert len(animated) <= 3 * 2 * 1024 * 1024
            assert not FRAME.search(read_for(.7)), 'finite motion did not stop'
            checks.append('Bitmap motion has finite local frames within paint and byte limits')
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 5, 12, 96, 80))
            small = read_for(.25)
            assert b'Resize' in small and not FRAME.search(small)
            checks.append('Insufficient viewport clears images and retains the resize fallback')
            os.write(master, b'q')
            process.wait(timeout=3)
            ending = read_for(.1)
            assert process.returncode == 0
            assert termios.tcgetattr(slave) == original
            assert b'\x1b[?1049l' in ending and b'\x1b[?25h' in ending
            assert b'a=d,d=I,i=' in complete and b'd=A' not in complete
            assert complete.count(b'\x1b[?2026h') == complete.count(b'\x1b[?2026l') > 0
            payload = bytearray()
            dimensions = None
            for header, chunk in re.findall(rb'\x1b_G([^;\x1b]*)(?:;([^\x1b]*))?\x1b\\', complete):
                values = dict(part.split(b'=') for part in header.split(b','))
                assert values.get(b'q') == b'2', 'graphics replies were not suppressed'
                if values.get(b'a') == b'd':
                    assert not payload, 'cleanup interrupted an image upload'
                    continue
                if b's' in values:
                    assert values.get(b'f') == b'24'
                    dimensions = int(values[b's']), int(values[b'v'])
                payload.extend(chunk)
                if values.get(b'm') == b'0':
                    decoded = base64.b64decode(payload, validate=True)
                    assert dimensions and len(decoded) == dimensions[0] * dimensions[1] * 3
                    payload.clear()
            assert not payload, 'incomplete image upload'
            checks.append('Owned Kitty images are deleted and terminal state is restored')
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            os.close(master)
            os.close(slave)
    print(json.dumps({'status': 'Pass', 'qualification': 'PTY protocol only', 'checks': checks}, indent=2))


if __name__ == '__main__':
    main()
