#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check the native mapped ingress boundary with bounded local Unix streams."""
import argparse
import array
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import struct
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--work-directory', type=Path, required=True)
    parser.add_argument('--binding-kind', choices=('application', 'authority'), default='application')
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    work = args.work_directory.resolve(strict=True)
    metadata = work.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise ValueError('work directory must be private and owned')
    root = Path(tempfile.mkdtemp(prefix='Ingress', dir=work))
    vector = json.loads((Path(__file__).resolve().parents[1] / 'Documentation/ApplicationRenewalVector.json').read_text())
    binding = dict(version=1, id=[1]*32, network=[2]*32, incarnation=[3]*32,
                   service=[4]*32, owner=list(bytes.fromhex(vector['owner'])),
                   endpoint=list(bytes.fromhex(vector['application'])), protocol='example/1')
    if args.binding_kind == 'authority':
        binding = dict(format='HyperNetAuthorityConnector/1', network='02'*32,
                       incarnation='03'*32, bootstrapDigest='04'*32, targetDigest='05'*32)
    parent, child = socket.socketpair()
    parent.settimeout(10)
    helper = peer = None
    try:
        helper = subprocess.Popen(['/usr/bin/podman', 'unshare', '--', str(binary), 'network', 'ingress-helper',
            '--directory', str(root/'Ingress'), '--descriptor', str(child.fileno()), '--binding-kind',args.binding_kind],
            pass_fds=[child.fileno()], stderr=subprocess.PIPE)
        child.close()
        body = json.dumps(binding, separators=(',', ':')).encode()
        parent.sendall(struct.pack('!I', len(body)) + body)

        def exact(length):
            data = b''
            while len(data) < length:
                part = parent.recv(length-len(data))
                if not part:
                    raise EOFError('helper stopped before readiness')
                data += part
            return data

        size = struct.unpack('!I', exact(4))[0]
        assert 0 < size <= 16384 and exact(size) == b'Ready'
        script = '''import os,socket,sys
os.chdir(sys.argv[1]);os.chroot('.');os.chdir('/')
if sys.argv[2]=='mapped':
 os.setgroups([]);os.setgid(1001);os.setuid(1001)
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(5);s.connect('/'+sys.argv[3])
if sys.argv[2]=='other':
 try:
  s.sendall(b'refused');assert s.recv(32)==b''
 except ConnectionResetError:pass
else:
 s.sendall(b'local descriptor');s.shutdown(socket.SHUT_WR)
 assert s.recv(32)==b'verified handoff'
'''
        tags = [('Control.sock', 1)]
        if args.binding_kind == 'application':
            tags.append(('Checks.sock', 2))
        for socket_name, tag in tags:
            refused = subprocess.run(['/usr/bin/podman', 'unshare', 'python3', '-S', '-c', script,
                str(root/'Ingress'), 'other', socket_name], capture_output=True, timeout=10)
            assert refused.returncode == 0, refused.stderr.decode()
            peer = subprocess.Popen(['/usr/bin/podman', 'unshare', 'python3', '-S', '-c', script,
                str(root/'Ingress'), 'mapped', socket_name], stderr=subprocess.PIPE)
            data, ancillary, flags, _ = parent.recvmsg(1, socket.CMSG_SPACE(4))
            assert data == bytes([tag]) and not flags and len(ancillary) == 1
            assert ancillary[0][:2] == (socket.SOL_SOCKET, socket.SCM_RIGHTS)
            descriptors = array.array('i'); descriptors.frombytes(ancillary[0][2])
            assert len(descriptors) == 1
            parent.sendall(b'\1')
            with socket.socket(fileno=descriptors[0]) as stream:
                stream.settimeout(5)
                assert stream.recv(32) == b'local descriptor'
                assert stream.recv(1) == b''
                stream.sendall(b'verified handoff')
            assert peer.wait(timeout=5) == 0, peer.stderr.read().decode()
        parent.close()
        assert helper.wait(timeout=5) == 0, helper.stderr.read().decode()
        print(json.dumps(dict(passed=True, binarySha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
            mappedUid=1001, wrongUidRefused=True, fdHandoff=True, halfClose=True,
            chroot=True, seccomp=True, bindingKind=args.binding_kind, descriptorTags=[tag for _, tag in tags])))
    finally:
        parent.close(); child.close()
        for process in (peer, helper):
            if process and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait(timeout=5)
        subprocess.run(['/usr/bin/podman', 'unshare', 'rm', '-rf', str(root)], check=True, timeout=10)


if __name__ == '__main__':
    main()
