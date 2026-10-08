#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check installed reader resizing, plain fallback and terminal restoration.

Input: installed HyperNetSuite path. Uses private temporary text and pseudoterminals.
No network, desktop terminal or graphics protocol is required.
"""
import fcntl
import json
import os
from pathlib import Path
import pty
import select
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import time


def read_until(master, marker, output, timeout=5):
    end=time.monotonic()+timeout
    while marker not in output and time.monotonic()<end:
        if select.select([master],[],[],.1)[0]:
            try: output += os.read(master,65536)
            except OSError: break
    assert marker in output, 'reader output did not reach expected state'
    return output


def session(binary, page, action):
    master,slave=pty.openpty()
    fcntl.ioctl(slave,termios.TIOCSWINSZ,struct.pack('HHHH',24,100,0,0))
    original=termios.tcgetattr(slave)
    process=subprocess.Popen([binary,'pages','preview',str(page),'--tui'],
        stdin=slave,stdout=slave,stderr=slave,env=dict(os.environ,TERM='xterm-256color'),start_new_session=True)
    output=b''
    try:
        output=read_until(master,b'Page content',output)
        if action=='resize':
            fcntl.ioctl(slave,termios.TIOCSWINSZ,struct.pack('HHHH',5,15,0,0)); process.send_signal(signal.SIGWINCH)
            output=read_until(master,b'Resize',b'')
            fcntl.ioctl(slave,termios.TIOCSWINSZ,struct.pack('HHHH',24,100,0,0)); process.send_signal(signal.SIGWINCH)
            output=read_until(master,b'Page content',b'')
            os.write(master,b'q')
        elif action=='interrupt-key': os.write(master,b'\x03')
        elif action=='terminate': process.send_signal(signal.SIGTERM)
        elif action=='interrupt-signal': process.send_signal(signal.SIGINT)
        elif action=='hangup': process.send_signal(signal.SIGHUP)
        elif action=='link': os.write(master,b'\t\r')
        else: os.write(master,b'q')
        process.wait(timeout=5)
        output=read_until(master,b'\x1b[?1049l',output)
        assert process.returncode==0
        assert termios.tcgetattr(slave)==original, 'terminal attributes were not restored'
        assert b'\x1b[?25h' in output, 'cursor was not restored'
    finally:
        if process.poll() is None: process.kill(); process.wait()
        os.close(master); os.close(slave)


def main():
    binary=str(Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory(prefix='HyperNetReader') as directory:
        page=Path(directory)/'Draft.txt'
        page.write_text('HyperNetPage/1\n# Terminal example\n: Unicode 世界 cafe\u0301\n=> https://example.com/ Reference\n')
        for action in ['quit','resize','interrupt-key','interrupt-signal','terminate','hangup','link']:
            session(binary,page,action)
            print('PASS',action,flush=True)
        plain=subprocess.run([binary,'pages','preview',str(page),'--tui','--ascii'],capture_output=True,check=True)
        assert b'\x1b' not in plain.stdout and b'\\u{4e16}' in plain.stdout and b'UNAPPROVED' in plain.stdout
        print('PASS pipe and ASCII fallback')
        page.write_bytes(b'HyperNetPage/1\n# Invalid\n: \xff\n')
        failed=subprocess.run([binary,'pages','preview',str(page)],capture_output=True)
        assert failed.returncode and b'\x1b' not in failed.stderr
        print('PASS malformed UTF-8 rejection')

if __name__=='__main__': main()
