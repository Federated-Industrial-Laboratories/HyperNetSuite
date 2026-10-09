#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise static layout, nested focus, colours and idle repaint in a real pseudoterminal.

Input: a built HyperNetSuite executable. Uses only synthetic pages and disposable PTYs.
No network, desktop terminal or installed service is changed.
"""
import fcntl
import json
import os
from pathlib import Path
import pty
import re
import select
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import time

CSI = re.compile(r'\x1b\[([0-9;?]*)([A-Za-z~])')
COLOUR = re.compile(rb'\x1b\[(?:3[0-7]m|9[0-7]m|38;)')


def screen(data, rows=120, columns=300):
    """Decode only the fixed cursor, erase and style controls emitted by this renderer."""
    text = data.decode('utf-8')
    cells = [[' '] * columns for _ in range(rows)]
    x = y = 0
    at = 0
    while at < len(text):
        if text[at] == '\x1b':
            match = CSI.match(text, at)
            assert match, 'unexpected terminal control'
            values, command = match.groups()
            if command in ('H', 'f'):
                point = [int(v or 1) for v in values.split(';')]
                y = point[0] - 1
                x = point[1] - 1 if len(point) > 1 else 0
                assert 0 <= y < rows and 0 <= x < columns, 'cursor escaped its viewport bound'
            elif command == 'J' and values == '2':
                cells = [[' '] * columns for _ in range(rows)]
            at = match.end()
        else:
            ch = text[at]
            if ch == '\r': x = 0
            elif ch == '\n': y += 1
            else:
                assert ch.isascii(), 'the PTY geometry fixture must remain ASCII'
                assert 0 <= y < rows and 0 <= x < columns, 'paint escaped its viewport bound'
                cells[y][x] = ch
                x += 1
            at += 1
    return [''.join(line).rstrip() for line in cells]


class Session:
    def __init__(self, binary, page, columns=96, rows=30, no_colour=False, term='xterm-256color'):
        self.master, self.slave = pty.openpty()
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack('HHHH', rows, columns, 0, 0))
        self.original = termios.tcgetattr(self.slave)
        env = dict(os.environ, TERM=term)
        env.pop('NO_COLOR', None)
        if no_colour: env['NO_COLOR'] = '1'
        self.process = subprocess.Popen([binary, 'pages', 'preview', str(page), '--tui'],
            stdin=self.slave, stdout=self.slave, stderr=self.slave, env=env, start_new_session=True)
        self.output = self.read(b'Page content')

    def read(self, marker=None, timeout=5):
        output = b''
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if select.select([self.master], [], [], .08)[0]:
                try: chunk = os.read(self.master, 65536)
                except OSError: break
                if not chunk: break
                output += chunk
            elif output and (marker is None or marker in output):
                return output
        assert marker is None or marker in output, 'expected renderer state was not reached'
        return output

    def key(self, value, marker=None):
        os.write(self.master, value)
        self.output = self.read(marker)
        return screen(self.output)

    def resize(self, columns, rows):
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack('HHHH', rows, columns, 0, 0))
        self.process.send_signal(signal.SIGWINCH)
        self.output = self.read(b'Page content')
        return screen(self.output)

    def close(self):
        try:
            if self.process.poll() is None:
                os.write(self.master, b'q')
                self.process.wait(timeout=5)
                self.output += self.read(timeout=.2)
            assert self.process.returncode == 0
            assert termios.tcgetattr(self.slave) == self.original, 'terminal state was not restored'
        finally:
            if self.process.poll() is None: self.process.kill(); self.process.wait()
            os.close(self.master)
            os.close(self.slave)


def find(rows, text):
    return next(index for index, row in enumerate(rows) if text in row)


def main():
    binary = str(Path(sys.argv[1]).resolve())
    checks = []
    with tempfile.TemporaryDirectory(prefix='HyperNetLayout') as directory:
        page = Path(directory) / 'Layout.txt'
        destination = 'https://example.invalid/' + 'a' * 140 + '/FINALDESTINATION'
        page.write_text('''HyperNetPage/2
# Layout fixture
@Row {"minChildColumns":12,"gap":2}
@Column {"weight":1,"colour":"Cyan"}
: LEFTCOLUMN
@End
@Column {"weight":3,"colour":"BrightGreen"}
: RIGHTCOLUMN
@End
@End
@ScrollBox {"id":"Outer","label":"OUTER","rows":4}
: OUTERFIRST
@ScrollBox {"id":"Inner","label":"INNER","rows":2}
: INNERONE
: INNERTWO
: INNERTHREE
@Button {"label":"DEEPBUTTON","action":{"kind":"Focus","target":"Inner"}}
@End
: OUTERLAST
@End
@Button {"label":"FOCUSINNER","action":{"kind":"Focus","target":"Inner"}}
@Button {"label":"SCROLLSTART","action":{"kind":"Scroll","target":"Inner","direction":"Start"}}
''' + f'=> {destination} EXTERNALREFERENCE\n')
        session = Session(binary, page)
        try:
            rows = screen(session.output)
            assert find(rows, 'LEFTCOLUMN') == find(rows, 'RIGHTCOLUMN')
            assert COLOUR.search(session.output)
            checks.append('wide weighted row and logical colour')
            rows = session.resize(25, 30)
            assert find(rows, 'RIGHTCOLUMN') > find(rows, 'LEFTCOLUMN')
            checks.append('narrow row stacks in document order')
            session.resize(96, 30)
            rows = session.key(b'\t\t\t', b'DEEPBUTTON')
            assert any('DEEPBUTTON' in row for row in rows[3:27])
            assert 'Focus: DEEPBUTTON' in rows[27]
            checks.append('Tab reveals control through nested viewport ancestors')
            rows = session.resize(25, 30)
            assert any('DEEPBUTTON' in row for row in rows[3:27])
            assert 'Focus: DEEPBUTTON' in rows[27]
            session.resize(96, 30)
            checks.append('resize preserves and reveals the selected nested control')
            rows = session.key(b'\r', b'ScrollBox: INNER')
            assert 'ScrollBox: INNER' in rows[27]
            rows = session.key(b'\x1b[H', b'INNERONE')
            assert any('INNERONE' in row for row in rows[3:27])
            rows = session.key(b'\x1b[F', b'DEEPBUTTON')
            assert any('DEEPBUTTON' in row for row in rows[3:27])
            checks.append('Focus action and independent Home/End scrolling')
            rows = session.key(b'\t\t\t\r', b'Scroll: SCROLLSTART')
            assert any('INNERONE' in row for row in rows[3:27])
            checks.append('Scroll button performs only its named local action')
            rows = session.key(b'\t', b'EXTERNALREFERENCE')
            rows = session.key(b'i', b'Trusted publication details')
            assert any('FINALDESTINATION' in row for row in rows)
            assert 'UNAPPROVED' in rows[1]
            checks.append('trusted details expose full long action destination')
            session.key(b'i', b'Page content')
            session.key(b'm', b'monochrome')
            assert not COLOUR.search(session.output)
            session.key(b'm', b'terminal colours')
            assert COLOUR.search(session.output)
            checks.append('reader monochrome toggle preserves labels')
            before = Path(f'/proc/{session.process.pid}/stat').read_text().split()
            ready = select.select([session.master], [], [], .4)[0]
            after = Path(f'/proc/{session.process.pid}/stat').read_text().split()
            assert not ready, 'idle page repainted without an input event'
            ticks = sum(map(int, after[13:15])) - sum(map(int, before[13:15]))
            assert ticks <= max(2, os.sysconf('SC_CLK_TCK') // 10), 'idle event loop consumed excessive CPU'
            checks.append('idle page emits no redraw and stays sleeping')
            session.resize(1000, 400)
            screen(session.output)
            checks.append('oversized terminal remains within300x120 viewport')
        finally: session.close()
        session = Session(binary, page, no_colour=True)
        try:
            assert not COLOUR.search(session.output)
            session.key(b'm', b'monochrome')
            assert not COLOUR.search(session.output)
            checks.append('NO_COLOR remains effective across toggle')
        finally: session.close()
        plain = subprocess.run([binary, 'pages', 'preview', str(page)], capture_output=True, check=True)
        assert b'\x1b' not in plain.stdout
        for marker in (b'INNERONE', b'INNERTHREE', b'DEEPBUTTON', b'OUTERLAST', b'FINALDESTINATION'):
            assert marker in plain.stdout
        checks.append('plain moderation includes clipped and offscreen content')
        session = Session(binary, page, term='dumb')
        try:
            session.process.wait(timeout=5)
            assert b'\x1b' not in session.output
            assert b'INNERTHREE' in session.output
            checks.append('TERM=dumb stays plain without terminal controls')
        finally: session.close()
    print(json.dumps({'status': 'Pass', 'checks': checks}, indent=2))


if __name__ == '__main__': main()
