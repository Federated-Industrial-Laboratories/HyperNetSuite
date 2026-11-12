#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Create small signed package fixtures; their inert binaries are never executed."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import time

ROOT = Path(__file__).resolve().parents[1]
destination = Path(sys.argv[1])
key = destination / 'Signer'
subprocess.run(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)], check=True)
publisher = key.with_suffix('.pub')
(destination / 'Packages').mkdir(mode=0o700)

for label, product, helper in [('Core', 'HyperNet', ROOT / 'Source/NativeInstallation/Package/Core'),
                               ('Suite', 'HyperNetSuite', ROOT / 'Tools')]:
    sys.path.insert(0, str(helper))
    spec = importlib.util.spec_from_file_location(label + 'FixtureBundle', helper / 'Bundle.py')
    bundle = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = bundle
    spec.loader.exec_module(bundle)
    names = ['Bin/' + product, 'Licence.txt', 'ReadMe.md', 'Tools/Bundle.py', 'Tools/PackageTrust.py',
             'Tools/Qualify.py', 'Documentation/ThirdPartyNotices.txt']
    if label == 'Core':
        names += ['ImageId.txt', 'Images/HyperNetOci.tar', 'Tools/Seccomp.sh',
                  'Documentation/SystemLibraries.tsv', 'Documentation/SystemLibraryNotices.txt']
    else:
        names += ['Tests/' + name + '.py' for name in ['ReaderTerminal', 'LayoutTerminal', 'MarkupRobustness', 'MediaImport', 'MediaTerminal']]
        names += ['Documentation/MediaSchema.json', 'Documentation/ApplicationStreams.md', 'Documentation/AuthorityConnector.md',
                  'SDK/README.md', 'SDK/Licence.txt', 'SDK/pyproject.toml', 'SDK/hypernet_streams/__init__.py',
                  'SDK/hypernet_streams/context.py', 'Examples/ApplicationStreams/stream_service.py',
                  'SDK/hypernet_streams-0.11.0-py3-none-any.whl']
        names += ['Examples/' + name for name in ['Prepare.py', 'ReadMe.md', 'Cafe.png', 'Square.svg', 'Books.svg', 'Botanical.svg']]
    payload = {name: b'Inert signed installer fixture; no native runtime.\n' for name in names}
    image = 'sha256:' + '1' * 64
    if label == 'Core':
        payload['ImageId.txt'] = (image + '\n').encode()
    runtime = {'elfInterpreter': '/lib64/ld-linux-x86-64.so.2', 'neededLibraries': ['libc.so.6'], 'glibcMinimum': '2.34'}
    binary_hash = hashlib.sha256(payload['Bin/' + product]).hexdigest()
    metadata = dict(runtime, binary='Bin/' + product, binarySha256=binary_hash,
                    prerequisites=['Synthetic signed installation fixture']) if label == 'Suite' else {
        'imageId': image, 'imageArchive': 'Images/HyperNetOci.tar', 'authoritySchema': 1, 'hostRuntime': runtime,
        'binaries': {'HyperNet': binary_hash, 'HyperNetGate': '2' * 64}, 'prerequisites': ['Synthetic signed installation fixture']}
    manifest = {'format': 1, 'product': product, 'version': '0.11.0', 'architecture': 'x86_64', 'metadata': metadata,
                'files': [{'path': name, 'size': len(data), 'mode': bundle.file_mode(name), 'sha256': hashlib.sha256(data).hexdigest()}
                          for name, data in sorted(payload.items())]}
    bundle.validate_manifest(manifest)
    folder = destination / 'Packages' / label
    folder.mkdir(parents=True, mode=0o700)
    base = folder / (product + '-0.11.0-linux-x86_64')
    archive = Path(str(base) + '.tar')
    with tarfile.open(archive, 'w', format=tarfile.USTAR_FORMAT) as sink:
        for name, data, mode in [('Manifest.json', bundle.encode(manifest), 0o600)] + [('Payload/' + n, d, bundle.file_mode(n)) for n, d in sorted(payload.items())]:
            info = tarfile.TarInfo(name)
            info.mode, info.size, info.mtime = mode, len(data), 0
            sink.addfile(info, io.BytesIO(data))
    archive.chmod(0o600)
    subprocess.run(['/usr/bin/ssh-keygen', '-Y', 'sign', '-n', product + 'Bundle1', '-f', str(key), str(archive)], check=True, capture_output=True)
    (folder / 'Publisher.pub').write_bytes(publisher.read_bytes())
    target = Path(str(base) + '.target.json')
    signed = subprocess.run([sys.executable, str(helper / 'Bundle.py'), 'Authorise', '--archive', str(archive), '--signature', str(archive) + '.sig',
                    '--public-key', str(publisher), '--signing-key', str(key), '--output', str(target), '--version-floor', '0.11.0',
                    '--state-contract', 'HyperNet080Authority2' if label == 'Core' else 'HyperNet080Client1', '--root-generation', '1',
                    '--sequence', '1', '--not-before', str(int(time.time()) - 1), '--expires', str(int(time.time()) + 3600)], capture_output=True)
    if signed.returncode:
        raise RuntimeError(signed.stderr.decode('utf-8', 'replace'))
    sys.path.pop(0)

fields = publisher.read_text().split()
print(json.dumps({'rootPin': hashlib.sha256((' '.join(fields[:2]) + '\n').encode()).hexdigest()}))
