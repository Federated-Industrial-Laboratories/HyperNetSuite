#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise native offline trust workflows and refusal boundaries without host services."""
import argparse
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(b'HyperNet/RecordDigest/1\0' + len(data).to_bytes(4, 'big') + data).hexdigest()


def encode(value):
    def header(kind, number):
        if number < 24:
            return bytes([kind * 32 + number])
        for tag, size in [(24, 1), (25, 2), (26, 4), (27, 8)]:
            if number < 1 << (8 * size):
                return bytes([kind * 32 + tag]) + number.to_bytes(size, 'big')
        raise ValueError('Integer overflow')
    if value is None:
        return b'\xf6'
    if type(value) is bool:
        return bytes([245 if value else 244])
    if type(value) is int:
        return header(0, value)
    if isinstance(value, bytes):
        return header(2, len(value)) + value
    if isinstance(value, str):
        data = value.encode()
        return header(3, len(data)) + data
    return header(4, len(value)) + b''.join(map(encode, value))


def decode(data):
    cursor = 0
    def item():
        nonlocal cursor
        first = data[cursor]
        cursor += 1
        if first in (244, 245, 246):
            return {244: False, 245: True, 246: None}[first]
        kind, argument = divmod(first, 32)
        if argument >= 24:
            size = 1 << (argument - 24)
            argument = int.from_bytes(data[cursor:cursor + size], 'big')
            cursor += size
        if kind == 0:
            return argument
        if kind == 4:
            return [item() for _ in range(argument)]
        value = data[cursor:cursor + argument]
        cursor += argument
        return value.decode() if kind == 3 else value
    value = item()
    require(cursor == len(data), 'Fixture decoder trailing bytes')
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('suite')
    parser.add_argument('--strace', default=shutil.which('strace'))
    args = parser.parse_args()
    binary = str(Path(args.suite).resolve())
    checks = []
    with tempfile.TemporaryDirectory(prefix='HyperNetOfflineClient') as temporary:
        root = Path(temporary)
        sequence = 0
        def run(arguments, ok=True, trace=True):
            nonlocal sequence
            sequence += 1
            trace_path = root / ('Trace' + str(sequence))
            command = [binary, *map(str, arguments)]
            if args.strace and trace:
                command = [args.strace, '-qq', '-f', '-e', 'trace=network', '-o', str(trace_path), '--', *command]
            result = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, timeout=20,
                                    env={'PATH': '', 'HOME': str(root), 'LANG': 'C', 'LC_ALL': 'C',
                                         'HTTP_PROXY': 'http://127.0.0.1:1', 'HTTPS_PROXY': 'http://127.0.0.1:1',
                                         'ALL_PROXY': 'socks5://127.0.0.1:1'})
            require((result.returncode == 0) == ok, 'Unexpected command result: ' + ' '.join(map(str, arguments[:2])) + ': ' + result.stderr.decode(errors='replace'))
            require(len(result.stdout) + len(result.stderr) < 131072, 'Unbounded command output')
            if trace_path.exists():
                require(not re.search(r'\b(socket|connect|bind|listen|accept|sendto|sendmsg|recvfrom|recvmsg)\(', trace_path.read_text()), 'Offline command attempted network syscall')
            return json.loads(result.stdout) if ok else result
        def write(path, data):
            path.write_bytes(data)
            path.chmod(0o600)
        def key(name):
            path = root / (name + '.json')
            value = run(['keygen', '--output', path])
            return value['publicKey'], path

        voters = sorted(key('Voter' + str(i))[0] for i in range(4))
        transports = {voter: key('AuthorityTransport' + str(i))[0] for i, voter in enumerate(voters)}
        monitor, _ = key('ClockMonitor')
        administrator, _ = key('Administrator')
        recoveries = sorted([key('Recovery' + str(i)) for i in range(3)])
        relay, _ = key('Relay')
        admission, _ = key('Admission')
        now = int(time.time() * 1000)
        spec = {'voters': voters, 'authorityTransports': transports, 'clockMonitors': [monitor],
                'administrator': administrator,
                'administratorActions': [9, 10, 11, 12, 13, 21, 22, 25, 27, 28],
                'enrolment': 'InvitationOnly', 'publicReading': False, 'minimumRoute': 'Independent',
                'publicationModes': ['HostReadable', 'Sealed'], 'defaultPublicationMode': 'HostReadable',
                'limits': [262144, 1024, 16, 16],
                'recovery': {'custody': 'OwnerThreshold', 'keys': [{'principal': '41' * 32, 'publicKey': k} for k, _ in recoveries],
                             'acceptedKeys': [k for k, _ in recoveries[:2]], 'immutableShared': False},
                'route': {'relayService': '42' * 32, 'relayOrigin': 'https://relay.invalid/', 'relayTransportKey': relay, 'relayDomain': '43' * 32,
                          'admissionService': '44' * 32, 'admissionOrigin': 'https://admission.invalid/', 'admissionTransportKey': admission,
                          'admissionDomain': '45' * 32, 'assurance': 'Independent', 'notBeforeMs': now - 60000, 'expiresMs': now + 600000}}

        def build(specification, label):
            source, draft, bundle = [root / (label + suffix) for suffix in ('Spec.json', 'Draft.cbor', 'Bootstrap.cbor')]
            write(source, json.dumps(specification).encode())
            drafted = run(['network', 'draft', '--spec', source, '--output', draft])
            require(drafted['currentAuthority'] is False and drafted['trust']['draft'] is True, 'Draft advertised active authority')
            pin = drafted['trust']['fingerprint']
            run(['network', 'inspect-bootstrap', '--bootstrap', draft])
            acceptances = []
            for public, identity in recoveries:
                if public not in specification['recovery']['acceptedKeys']:
                    continue
                acceptance = root / (label + public + '.cbor')
                run(['network', 'recovery-accept', '--draft', draft, '--fingerprint', pin, '--identity', identity, '--output', acceptance])
                acceptances.append(acceptance)
            assembled = run(['network', 'assemble', '--draft', draft, '--acceptance', *acceptances, '--output', bundle])
            require(assembled['trust']['draft'] is False, 'Complete bootstrap is still a draft')
            return bundle, assembled['trust']['fingerprint'], draft, acceptances

        bundle, pin, draft, acceptances = build(spec, 'Independent')
        profile = root / 'Client.json'
        prepared = run(['network', 'prepare', '--bootstrap', bundle, '--fingerprint', pin, '--output', profile])
        require(prepared['state'] == 'OfflinePrepared' and prepared['hostingRoles'] == [] and prepared['membership'] is False
                and prepared['inboundListeners'] is False and prepared['currentAuthority'] is False, 'Client acquired implicit authority')
        require(prepared['devicePublicKey'] != prepared['relayPublicKey'], 'Client and relay keys coincide')
        require(stat.S_IMODE(profile.stat().st_mode) == 0o600, 'Profile is not private')
        original = profile.read_bytes()
        inspection = run(['network', 'inspect', '--profile', profile])
        require('secretKey' not in json.dumps(inspection), 'Inspection exposed keys')
        require(inspection['trust']['authorityTransports'] == transports
                and inspection['trust']['clockMonitors'] == [monitor],
                'Inspection omitted the accepted authority transport or clock identities')
        governance_summary = inspection['trust']['genesisGovernance']
        grant_summary = governance_summary['rootGrants'][0]
        tier_summary = governance_summary['tiers'][0]
        policy_summary = governance_summary['networkPolicy']
        expected_limits = dict(zip(['maxBytes', 'maxObjects', 'maxConnections', 'maxConcurrentOperations'], spec['limits']))
        require(policy_summary['limits'] == grant_summary['limits'] == tier_summary['limits'] == expected_limits
                and policy_summary['manualReviewDefault'] is True, 'Inspection omitted effective policy limits or review default')
        require([value['code'] for value in grant_summary['actions']] == spec['administratorActions']
                and grant_summary['actions'][0]['name'] == 'AdministerPolicy'
                and grant_summary['subject'] == administrator and grant_summary['issuer'] == administrator,
                'Inspection omitted administrator capabilities')
        require(grant_summary['tier'] == tier_summary['record'] and policy_summary['policyAuthority'] == [grant_summary['record']]
                and grant_summary['scopes'] == [{'code': 0, 'kind': 'Network', 'id': inspection['trust']['network']}]
                and grant_summary['validity'] == {'notBeforeMs': spec['route']['notBeforeMs'], 'expiresMs': spec['route']['expiresMs']}
                and grant_summary['remainingDelegationDepth'] == tier_summary['maximumDelegationDepth'] == 8,
                'Inspection omitted exact grant references, scopes, validity or delegation')
        require(inspection['trust']['bootstrapTimeMs'] == decode(decode(bundle.read_bytes())[2])[9]
                and governance_summary['recoveryPolicy']['threshold'] == 2,
                'Inspection omitted bootstrap time or recovery threshold')
        changed_spec = copy.deepcopy(spec)
        changed_spec['administratorActions'] = [9]
        changed_spec['limits'] = [4096, 128, 2, 1]
        changed_spec_path, changed_draft = root / 'RestrictedSpec.json', root / 'RestrictedDraft.cbor'
        write(changed_spec_path, json.dumps(changed_spec).encode())
        run(['network', 'draft', '--spec', changed_spec_path, '--output', changed_draft])
        restricted = run(['network', 'inspect-bootstrap', '--bootstrap', changed_draft])['trust']['genesisGovernance']
        require(restricted['rootGrants'][0]['subject'] == administrator
                and restricted['rootGrants'][0]['actions'] == [{'code': 9, 'name': 'AdministerPolicy'}]
                and restricted['rootGrants'][0]['limits']['maxBytes'] == restricted['networkPolicy']['limits']['maxBytes'] == 4096,
                'Same-administrator policy changes are hidden by inspection')
        join = run(['network', 'join', '--profile', profile], ok=False)
        require(b'--invitation' in join.stderr, 'Join must require explicit authenticated invitation material')
        run(['--config', profile, 'status'], ok=False)
        run(['network', 'prepare', '--bootstrap', bundle, '--fingerprint', pin, '--output', profile], ok=False)
        require(profile.read_bytes() == original, 'Retry changed existing identity')
        checks.append('Native draft, separately signed custody, assembly and client-only offline lifecycle')

        failed = root / 'Refused.json'
        def refuse(data, expected_pin=None):
            source = root / 'Untrusted.cbor'
            write(source, data)
            run(['network', 'prepare', '--bootstrap', source, '--fingerprint', expected_pin or digest(data), '--output', failed], ok=False)
            require(not failed.exists(), 'Refused bootstrap created a profile')
        raw = bundle.read_bytes()
        refuse(raw, '00' * 32)
        refuse(draft.read_bytes())
        for data in [b'\x98\x06' + raw[1:], raw + b'\0', b'\x81' * 18 + b'\0', b'\x9f\xff', b'\xa0', b'\xf7', b'\x99\x10\x01']:
            refuse(data)
        changed = decode(raw)
        route = decode(changed[5])
        route[5] = 'https://substitution.invalid/'
        changed[5] = encode(route)
        refuse(encode(changed), pin)
        for slot, value in [(5, 'https://relay.invalid/\x1b]2;Title'), (12, 2), (7, b'\0' * 32), (10, bytes.fromhex(relay))]:
            changed = decode(raw)
            route = decode(changed[5]); route[slot] = value; changed[5] = encode(route)
            refuse(encode(changed))
        checks.append('Whole-bootstrap pins, canonical records and route substitution refusals')

        def governance_mutation(change):
            changed = decode(raw)
            descriptor = decode(changed[2])
            governance = decode(changed[3])
            records = [decode(v) for v in governance[4]]
            change(descriptor, records)
            governance[4] = [encode(v) for v in records]
            changed[3] = encode(governance)
            descriptor[6] = bytes.fromhex(digest(governance[4][0]))
            descriptor[7] = bytes.fromhex(digest(governance[4][3]))
            descriptor[8] = bytes.fromhex(digest(changed[3]))
            changed[2] = encode(descriptor)
            return encode(changed)
        def narrow_grant(_descriptor, records):
            tier, grant = records[1:3]
            tier[7], tier[8], tier[10], tier[11] = 42, 'Restricted administrator', [[3, b'\x55' * 32]], 2
            grant[9][3] = bytes.fromhex(digest(encode(tier)))
            grant[11], grant[12], grant[14] = tier[10], [now - 1000, now + 300000], 1
        narrowed = governance_mutation(narrow_grant)
        narrowed_path, narrowed_profile = root / 'NarrowedBootstrap.cbor', root / 'NarrowedClient.json'
        write(narrowed_path, narrowed)
        narrowed_summary = run(['network', 'prepare', '--bootstrap', narrowed_path, '--fingerprint', digest(narrowed), '--output', narrowed_profile])['trust']['genesisGovernance']
        grant = narrowed_summary['rootGrants'][0]
        require(grant['scopes'] == [{'code': 3, 'kind': 'Service', 'id': '55' * 32}]
                and grant['validity']['expiresMs'] == now + 300000 and grant['remainingDelegationDepth'] == 1
                and narrowed_summary['tiers'][0]['rank'] == 42 and narrowed_summary['tiers'][0]['label'] == 'Restricted administrator'
                and grant['tier'] == narrowed_summary['tiers'][0]['record'], 'Imported tier, scope and validity changes are hidden')
        checks.append('Complete public governance inspection distinguishes actions, limits, tier references, scopes and validity')
        refuse(governance_mutation(lambda d, r: d[5].__setitem__(0, b'\0' * 32)))
        refuse(governance_mutation(lambda d, r: d[5].__setitem__(0, d[5][1])))
        refuse(governance_mutation(lambda d, r: r[2].__setitem__(8, d[5][0])))
        refuse(governance_mutation(lambda d, r: r[2][10].append(32)))
        refuse(governance_mutation(lambda d, r: r[2][9].__setitem__(3, b'\x51' * 32)))
        refuse(governance_mutation(lambda d, r: r[0].__setitem__(15, [b'\x52' * 32])))
        changed = decode(raw)
        envelope = decode(changed[4]); envelope[3].append(envelope[3][0]); changed[4] = encode(envelope)
        refuse(encode(changed))
        changed = decode(raw)
        envelope = decode(changed[4]); envelope[3] = envelope[3][:1]; changed[4] = encode(envelope)
        refuse(encode(changed))
        run(['network', 'assemble', '--draft', draft, '--acceptance', acceptances[0], acceptances[0], '--output', failed], ok=False)
        run(['network', 'recovery-accept', '--draft', draft, '--fingerprint', digest(draft.read_bytes()), '--identity', recoveries[2][1], '--output', failed], ok=False)
        require(not failed.exists(), 'Invalid recovery acceptance published output')
        checks.append('Re-pinned malformed governance, exact references and custody thresholds refused')

        organisational = copy.deepcopy(spec)
        organisational['minimumRoute'] = organisational['route']['assurance'] = 'Organisational'
        organisational['route']['admissionDomain'] = organisational['route']['relayDomain']
        org, org_pin, _, _ = build(organisational, 'Organisation')
        refuse(org.read_bytes())
        org_profile = root / 'OrganisationClient.json'
        accepted = run(['network', 'prepare', '--bootstrap', org, '--fingerprint', org_pin, '--minimum-route', 'Organisational', '--output', org_profile])
        require('correlate' in accepted['privacyAssumption'], 'Organisational privacy guarantee is unclear')
        shared = copy.deepcopy(spec)
        shared['recovery']['custody'] = 'SharedThreshold'
        shared['recovery']['immutableShared'] = True
        for number, item in enumerate(shared['recovery']['keys']):
            item['principal'] = bytes([70 + number]).hex() * 32
        build(shared, 'Shared')
        checks.append('Independent default, explicit organisational alternative and distinct shared custodians')

        link = root / 'Link.cbor'; link.symlink_to(bundle)
        run(['network', 'prepare', '--bootstrap', link, '--fingerprint', pin, '--output', failed], ok=False)
        link.unlink(); os.link(bundle, link)
        run(['network', 'prepare', '--bootstrap', link, '--fingerprint', pin, '--output', failed], ok=False)
        link.unlink()
        directory_link = root / 'LinkedDirectory'; directory_link.symlink_to(root, target_is_directory=True)
        run(['network', 'prepare', '--bootstrap', directory_link / bundle.name, '--fingerprint', pin, '--output', failed], ok=False)
        profile.chmod(0o644)
        run(['network', 'inspect', '--profile', profile], ok=False)
        profile.chmod(0o600)
        os.link(profile, root / 'ProfileHardlink')
        run(['network', 'inspect', '--profile', profile], ok=False)
        (root / 'ProfileHardlink').unlink()
        public = root / 'Public'; public.mkdir(mode=0o755); public.chmod(0o755)
        run(['network', 'prepare', '--bootstrap', bundle, '--fingerprint', pin, '--output', public / 'Client.json'], ok=False)
        racing = root / 'Race.json'
        def race():
            return subprocess.run([binary, 'network', 'prepare', '--bootstrap', str(bundle), '--fingerprint', pin, '--output', str(racing)],
                                  stdin=subprocess.DEVNULL, capture_output=True, timeout=20, env={'PATH': '', 'HOME': str(root)})
        with ThreadPoolExecutor(max_workers=2) as pool:
            a, b = list(pool.map(lambda _: race(), range(2)))
        require(sorted([a.returncode == 0, b.returncode == 0]) == [False, True], 'Concurrent creation did not preserve one winner')
        run(['network', 'inspect', '--profile', racing])
        lock_path = root / ('Network' + hashlib.sha256(profile.name.encode()).hexdigest() + '.lock')
        with lock_path.open('r+b') as locked:
            fcntl.flock(locked, fcntl.LOCK_EX | fcntl.LOCK_NB)
            run(['network', 'remove', '--profile', profile, '--fingerprint', pin], ok=False)
            run(['network', 'prepare', '--bootstrap', bundle, '--fingerprint', pin, '--output', profile], ok=False)
            require(profile.read_bytes() == original, 'Locked profile was changed')
        run(['network', 'remove', '--profile', profile, '--fingerprint', '00' * 32], ok=False)
        require(profile.read_bytes() == original, 'Wrong removal identity changed profile')
        run(['network', 'remove', '--profile', profile, '--fingerprint', pin])
        require(not profile.exists() and org_profile.exists() and bundle.exists(), 'Removal affected adjacent state')
        replacement = run(['network', 'prepare', '--bootstrap', bundle, '--fingerprint', pin, '--output', profile])
        require(replacement['devicePublicKey'] != prepared['devicePublicKey'] and lock_path.exists(), 'Profile recreation reused old keys or removed stable lock')
        saved = json.loads(profile.read_bytes())
        expired = decode(raw)
        route = decode(expired[5]); route[14] = now - 1; expired[5] = encode(route)
        saved['bootstrap'] = encode(expired).hex(); saved['fingerprint'] = digest(encode(expired))
        write(profile, json.dumps(saved).encode())
        require(run(['network', 'inspect', '--profile', profile])['bootstrapTimeValid'] is False, 'Expired profile advertised current bootstrap')
        refuse(encode(expired))
        run(['network', 'remove', '--profile', profile, '--fingerprint', saved['fingerprint']])
        checks.append('Private descriptor-relative files, no-clobber concurrency and exact-profile removal')
    print(json.dumps({'status': 'Passed', 'binarySha256': hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
                      'checks': checks, 'networkSyscallObservationEnabled': bool(args.strace),
                      'observedNetworkSyscalls': 0 if args.strace else None, 'networkUsed': False,
                      'hostToolsRequiredByClient': False, 'privacyDeploymentQualified': False}, sort_keys=True))


if __name__ == '__main__':
    main()
