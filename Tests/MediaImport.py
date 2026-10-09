#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise a built import worker, confinement, static conversion and safe file boundaries.

Input: HyperNetSuite executable. All inputs and outputs are disposable local files.
No service, external network or desktop application is used.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import time
import zlib

JPEG = '/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAIBAQEBAQIBAQECAgICAgQDAgICAgUEBAMEBgUGBgYFBgYGBwkIBgcJBwYGCAsICQoKCgoKBggLDAsKDAkKCgr/2wBDAQICAgICAgUDAwUKBwYHCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgr/wAARCAACAAMDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwD5nooor+Sz/XA//9k='


def chunk(kind, data):
    return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data))


def png(width, height, rgba):
    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, 6, 0, 0, 0))
            + chunk(b'IDAT', zlib.compress(b''.join(b'\0' + rgba * width for _ in range(height))))
            + chunk(b'IEND', b''))


def main():
    binary = str(Path(sys.argv[1]).resolve())
    checks = []
    with tempfile.TemporaryDirectory(prefix='HyperNetMediaImport') as temporary:
        root = Path(temporary)
        def call(source, name, ok=True):
            output, manifest = root / (name + '.AssetBytes'), root / (name + '.Manifest')
            result = subprocess.run([binary, 'media', 'import', '--input', str(source), '--output', str(output),
                '--manifest', str(manifest), '--id', 'Picture', '--host', '1' * 64], capture_output=True, timeout=8)
            assert (result.returncode == 0) == ok, (name, result.stderr.decode(errors='replace'))
            if ok:
                value = json.loads(manifest.read_text())
                data = output.read_bytes()
                assert value['digest'] == hashlib.sha256(data).hexdigest()
                assert value['bytes'] == len(data)
                assert value['width'] * value['height'] <= 262144
                assert max(value['width'], value['height']) <= 1024
                assert output.stat().st_mode & 0o777 == 0o600
                return value, data, result
            assert not output.exists() and not manifest.exists()
            return result
        source = root / 'Input.png'
        source.write_bytes(png(2, 2, bytes([255, 0, 0, 128])))
        value, data, result = call(source, 'Png')
        assert data == bytes([255, 127, 127]) * 4
        assert 'metadata removed' in result.stdout.decode()
        checks.append('PNG alpha is composited and output hash/length/dimensions match')
        jpeg = root / 'Input.jpg'
        jpeg.write_bytes(base64.b64decode(JPEG))
        value, data, _ = call(jpeg, 'Jpeg')
        assert (value['width'], value['height'], len(data)) == (3, 2, 18)
        checks.append('JPEG import produces canonical RGB')
        source.write_bytes(png(1024, 1024, bytes([0, 128, 255, 255])))
        value, data, _ = call(source, 'Reduced')
        assert (value['width'], value['height'], len(data)) == (512, 512, 786432)
        checks.append('Oversized decoded image reduces to the pixel budget')
        raw = b'\0' + b''.join(bytes([sector, 0, 0, 255]) * 1_000_000 for sector in range(16))
        source.write_bytes(b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', 16_000_000, 1, 8, 6, 0, 0, 0))
            + chunk(b'IDAT', zlib.compress(raw)) + chunk(b'IEND', b''))
        del raw
        value, data, _ = call(source, 'Panorama')
        assert (value['width'], value['height']) == (1024, 1)
        assert data == b''.join(bytes([x // 64, 0, 0]) for x in range(1024))
        checks.append('Extreme valid panorama sampling cannot overflow coordinate multiplication')
        svg = root / 'Input.svg'
        svg.write_text('<svg xmlns="http://www.w3.org/2000/svg" width="8" height="4"><script>bad()</script>'
            '<rect width="8" height="4" fill="red" onclick="bad()"/></svg>')
        value, data, result = call(svg, 'Vector')
        vector = json.loads(data)
        assert value['profile'] == 'HyperNetVector/1' and len(vector['paths']) == 1
        assert b'script' not in data and b'onclick' not in data
        assert b'SVG scripts removed' in result.stdout and b'SVG event handlers removed' in result.stdout
        rendered = subprocess.run([binary, '--internal-media-worker'], input=struct.pack('<I', 0xffffffff) + data,
            capture_output=True, timeout=6, env={})
        assert rendered.returncode == 0, rendered.stderr
        size = struct.unpack('<I', rendered.stdout[:4])[0]
        header = json.loads(rendered.stdout[4:4 + size])
        assert header['profile'] == 'HyperNetRaster/1'
        assert rendered.stdout[4 + size:] == bytes([255, 0, 0]) * 32
        checks.append('SVG active content is reported and retained geometry rasterises under confinement')
        export = root / 'Export.svg'
        result = subprocess.run([binary, 'media', 'export-svg', '--input', str(root / 'Vector.AssetBytes'), '--output', str(export)],
            capture_output=True, timeout=6)
        assert result.returncode == 0, result.stderr
        assert b'<path' in export.read_bytes() and b'script' not in export.read_bytes()
        checks.append('Canonical geometry exports as static SVG')
        for index, bad in enumerate([
            '<!DOCTYPE svg [<!ENTITY x SYSTEM "file:///etc/passwd">]><svg width="4" height="4"/>',
            '<svg width="4" height="4"><image href="https://example.invalid/image.png"/></svg>',
            '<svg width="4" height="4"><foreignObject/></svg>',
            '<svg width="4" height="4"><text>Unsupported font content</text></svg>',
            '<svg width="4" height="4"><animate attributeName="fill"/></svg>',
            '<svg width="4" height="4"><rect width="4" height="4" filter="url(#effect)"/></svg>',
            '<svg width="4" height="4"><rect width="4" height="4" style="position:absolute"/></svg>',
            '<svg width="20" height="20"><rect x="4" y="4" width="12" height="12" fill="red" stroke="red" stroke-width="4" opacity=".5"/></svg>',
        ]):
            svg.write_text(bad)
            call(svg, 'Rejected' + str(index), False)
        checks.append('DTD, external references, executable/unsupported visual constructs are refused')
        source.write_bytes(b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', 16000001, 1, 8, 6, 0, 0, 0)) + chunk(b'IEND', b''))
        call(source, 'HugeHeader', False)
        source.write_bytes(b'not an image')
        call(source, 'Malformed', False)
        checks.append('Malformed inputs and oversized dimensions are refused')
        fifo = root / 'InputPipe'
        os.mkfifo(fifo)
        start = time.monotonic()
        call(fifo, 'Pipe', False)
        assert time.monotonic() - start < 2
        link = root / 'Link.png'
        link.symlink_to(source)
        call(link, 'Link', False)
        checks.append('Named pipes and symlink inputs fail before decoding')
        probe = subprocess.run([binary, '--internal-media-worker'], input=b'\0' * 4, capture_output=True, env={}, timeout=6)
        assert probe.returncode == 0, probe.stderr
        assert all(json.loads(probe.stdout).values())
        checks.append('Worker refuses filesystem, network, sockets, processes and inherited descriptors')
    print(json.dumps({'status': 'Pass', 'checks': checks}, indent=2))


if __name__ == '__main__':
    main()
