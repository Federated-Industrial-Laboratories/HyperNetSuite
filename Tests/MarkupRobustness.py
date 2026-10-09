#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded deterministic mutation smoke check through the installed page parser.

Input: HyperNetSuite binary. Reject crashes, hangs and terminal controls. This
check is not an exhaustive parser or Unicode correctness proof.
"""
import hashlib
import json
from pathlib import Path
import random
import subprocess
import sys
import tempfile

binary=Path(sys.argv[1]).resolve()
generator=random.Random(0x4859504552)
base=b'HyperNetPage/2\n# Sample\n: Text with a bounded paragraph.\n=> https://example.com/ Link\n'
accepted=0
with tempfile.TemporaryDirectory(prefix='HyperNetMarkup') as directory:
    path=Path(directory)/'Input.txt'
    cases=[b'',b'\xff',base+b': '+b'x'*16384+b'\n',base+b': '+b'a\xcc\x81'*600+b'\n']
    for _ in range(256):
        value=bytearray(base)
        for _ in range(generator.randint(1,8)):
            position=generator.randrange(len(value))
            value[position]=generator.randrange(256)
        cases.append(bytes(value))
    for source in cases:
        path.write_bytes(source)
        result=subprocess.run([str(binary),'pages','preview',str(path),'--ascii'],capture_output=True,timeout=2)
        assert result.returncode in (0,1), 'parser terminated unexpectedly'
        assert len(result.stdout)+len(result.stderr)<131072, 'output exceeded its bound'
        for stream in [result.stdout,result.stderr]:
            assert not any(byte<32 and byte!=10 or byte==127 for byte in stream), 'terminal control escaped'
        accepted+=result.returncode==0
print(json.dumps({'cases':len(cases),'accepted':accepted,'rejected':len(cases)-accepted,
                  'binarySha256':hashlib.sha256(binary.read_bytes()).hexdigest()}))
