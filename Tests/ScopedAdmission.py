# SPDX-License-Identifier: MIT
"""Exercise packaged native admission against an already running private route fixture."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

FORMAT = 'HyperNetNativeAdmission/1'


def receive(stream, size):
    result = bytearray()
    while len(result) < size:
        data = stream.recv(size-len(result))
        assert data, 'Application stream closed before its bounded message'
        result.extend(data)
    return bytes(result)


def run(workflow):
    """The fixture supplies live authority, relay and application routes and cleans them up."""
    w = workflow
    root = w.root / 'NativeAdmission'
    root.mkdir(mode=0o700)
    candidate = root / 'Candidate'
    candidate.mkdir(mode=0o700)
    (candidate / 'Clock').mkdir(mode=0o700)
    registrar = Ed25519PrivateKey.generate()
    descriptor = Ed25519PrivateKey.generate()
    w.actor('NativeRegistrar', registrar)
    policy = os.urandom(32).hex()
    spec = dict(id=policy, parent=w.c['grant'],
                registrar=w.c['public_key'](registrar).hex(),
                descriptor=w.c['public_key'](descriptor).hex(), maximumSlots=1,
                validity=[int(time.time()*1000)-1500, w.expiry],
                relay=w.relay['route_id'], authority=w.authority['route_id'],
                templates=[dict(role=0, destination=w.application['route_id'], application=None,
                    limits=[262144,1024,16,16], connections=64, bytes=16777216,voucherMs=120000),
                    dict(role=1, destination=w.application['route_id'],
                    application=w.app_id, limits=[262144, 1024, 16, 16],
                    connections=64, bytes=16777216, voucherMs=120000)], legacy=[], enabled=True)
    path = root/'Policy.json'
    w.write(path, json.dumps(spec).encode())
    w.client('Administrator', ['authority-inspection', 'admission', 'policy'],
             ['--spec', w.put('Administrator', path)])
    config = dict(format='HyperNetAdmissionRegistrar/1', bootstrap='/Client/Bootstrap.cbor',
                  bootstrapDigest=w.c['pin'], directory='/State/OperatorFloor',
                  clockWitness='/Clock/ClockHealth.cbor', clockMonitorKey=w.c['public']['publicKey'],
                  hostKernelBoot=w.c['public']['kernelBoot'], keyFile='/Client/Identity.json',
                  socket='/Client/Control.sock', policy=policy)
    path = root/'Registrar.json'
    w.write(path, json.dumps(config).encode())
    configuration = w.put('NativeRegistrar', path)
    base = w.client_args('NativeRegistrar', ['authority-inspection'])
    base = base[:base.index('authority-inspection')]
    base.insert(3, '--interactive')
    registrar_command = [*base, 'authority-inspection', 'admission', 'registrar',
                         '--configuration', configuration, '--json-stdin']
    candidate_command = [str(w.c['suite']), 'authority-inspection', 'admission', 'candidate',
                         '--directory', str(candidate), '--clock-witness',
                         str(w.reader_clock/'ClockHealth.json'), '--json-stdin']
    sequence = 0

    def call(command, body, expected=None):
        nonlocal sequence
        sequence += 1
        remaining = w.deadline-time.monotonic()
        assert remaining > 0, 'Admission fixture reached its original deadline'
        env = os.environ.copy()
        env.pop('TMPDIR', None)
        result = subprocess.run(command, input=json.dumps(dict(format=FORMAT, body=body)).encode(),
                                capture_output=True, timeout=min(60, remaining), env=env)
        assert len(result.stdout)+len(result.stderr) <= 8*1024*1024
        if expected == 'error':
            assert result.returncode != 0 and result.stderr
            w.c['report']['cases'].append(dict(case='NativeAdmission'+str(sequence),
                operation=body['operation'], status='rejected', passed=True))
            return None
        assert result.returncode == 0, result.stderr.decode(errors='replace')
        response = json.loads(result.stdout)
        assert response['format'] == FORMAT
        value = response['body']
        if expected:
            assert value['status'] == expected, value['status']
        w.c['report']['cases'].append(dict(case='NativeAdmission'+str(sequence),
            operation=body['operation'], status=value['status'], outputBytes=len(result.stdout),
            artifactBytes={key:len(bytes.fromhex(value[key])) for key in
                ('bootstrap','proof','challenge','result') if key in value}, passed=True))
        return value

    def reg(operation, expected=None, **fields):
        return call(registrar_command, dict(operation=operation, **fields), expected)

    def local(operation, expected=None, **fields):
        return call(candidate_command, dict(operation=operation, **fields), expected)

    description = reg('describe', 'descriptor')
    inspected = local('inspect', 'descriptor', bootstrap=description['bootstrap'],
        proof=description['proof'], expectedKey=description['currentKey'])
    for key in ('accessEnd','maximumParticipants','roles'):
        assert inspected[key] == description[key]
    assert inspected['accessEnd'] == spec['validity'][1]
    assert inspected['maximumParticipants'] == 1 and inspected['roles'] == [0,1]
    prepared = local('prepare', 'prepared', bootstrap=description['bootstrap'],
        proof=description['proof'], expectedKey=description['currentKey'], roles=[0,1], minimumRoute=1 if w.assurance=='Independent' else 0)
    assert len(prepared['roles']) == 2
    roles = prepared['roles']
    application = hashlib.sha256(b'exact accepted application request').hexdigest()
    request = hashlib.sha256(json.dumps(roles, sort_keys=True).encode()).hexdigest()
    next_ordinal = description['claimFloor']+1
    claim = next_ordinal.to_bytes(8, 'big').hex()+os.urandom(24).hex()
    offered = reg('challenge', 'challenge', claim=claim, requestDigest=request,
                  roles=roles, applicationBinding=application)
    accepted = local('acceptChallenge', 'acceptance', challenge=offered['challenge'],
                     applicationBinding=application, requestDigest=request, claim=claim)
    reg('enrol', 'error', challenge=offered['challenge'], acceptance='80')
    ready = reg('enrol', 'ready', challenge=offered['challenge'], acceptance=accepted['acceptance'])
    assert ready['principals'] == [{key: role[key] for key in ('role', 'member', 'relay')} for role in roles]
    installed = local('acceptResult', 'installed', result=ready['result'])
    assert len(installed['profiles']) == 2
    profile = next(role for role in installed['profiles'] if role['role']==1)
    floor = Path(profile['directory'])/'Requester/AuthorityFloor.json'
    # The normal native client uses only the installed relay route, without a local authority socket.
    result = subprocess.run([str(w.c['suite']), 'network', 'connect', '--profile', profile['profile'],
        '--', 'streams', 'lookup', '--grant', profile['connectGrant'], '--service', w.app_id],
        capture_output=True, timeout=min(45, w.deadline-time.monotonic()))
    assert result.returncode == 0, result.stderr.decode(errors='replace')
    w.c['report']['cases'].append(dict(case='NativeAdmissionClientLookup', passed=True,
        transportPrincipal=profile['member'], routeOnly=True))
    retry = reg('enrol', 'ready', challenge=offered['challenge'], acceptance=accepted['acceptance'])
    assert retry['binding'] == installed['binding']
    companion = root/'Companion'
    targets = root/'Targets.json'
    w.write(targets,json.dumps([dict(service=w.app_id,protocol=w.protocol,grant=profile['connectGrant'],route=profile['destinationRoute'],renewalMs=60000)]).encode())
    log = (w.c['evidence']/(w.c['label']+'NativeAdmissionCompanion.log')).open('wb')
    w.logs.append(log)
    process = subprocess.Popen([str(w.c['suite']),'network','connect','--profile',profile['profile'],
        '--','streams','agent','--ipc-directory',str(companion),'--targets',str(targets)],stdout=log,stderr=subprocess.STDOUT)
    w.processes.append(process)
    until=min(w.deadline,time.monotonic()+20)
    while not (companion/'Control.sock').exists():
        assert process.poll() is None and time.monotonic()<until,'Scoped companion did not start'
        time.sleep(.1)
    endpoint=w.Agent(w.agent_root,version=2)
    actor=w.Agent(companion,version=2)
    with ThreadPoolExecutor(max_workers=1) as pool:
        receiving=pool.submit(endpoint.accept,timeout=20)
        outgoing=actor.connect(w.app_id,w.protocol,timeout=20)
        incoming=receiving.result(timeout=20)
    outgoing.socket.settimeout(min(10,w.deadline-time.monotonic()))
    incoming.socket.settimeout(min(10,w.deadline-time.monotonic()))
    outgoing.sendall(b'before renewal')
    assert receive(incoming,14)==b'before renewal'
    renewed = reg('renewalChallenge', 'challenge', binding=installed['binding'])
    proof = local('renewalProof', 'acceptance', challenge=renewed['challenge'])
    ready = reg('renew', 'ready', binding=installed['binding'], proof=proof['acceptance'])
    local('acceptResult', 'installed', result=ready['result'],roles=[0])
    assert process.poll() is None
    outgoing.sendall(b'after renewal')
    assert receive(incoming,13)==b'after renewal'
    outgoing.close();incoming.close()
    process.terminate();assert process.wait(timeout=10) in (0,-15)
    local('acceptResult','installed',result=reg('status','ready',binding=installed['binding'])['result'],roles=[1])
    w.c['report']['cases'].append(dict(case='NativeAdmissionReaderRefreshWithLiveChat',passed=True))
    retired = reg('revoke', 'retired', binding=installed['binding'], reason='Explicit test retirement')
    local('acceptResult', 'retired', result=retired['result'])
    # The next slot assignment reuses local keys and a retained floor, never a fresh identity.
    description = reg('describe', 'descriptor')
    next_ordinal = description['claimFloor']+1
    claim = next_ordinal.to_bytes(8, 'big').hex()+os.urandom(24).hex()
    offered = reg('challenge', 'challenge', claim=claim, requestDigest=request,
                  roles=roles, applicationBinding=application)
    accepted = local('acceptChallenge', 'acceptance', challenge=offered['challenge'],
                     applicationBinding=application, requestDigest=request, claim=claim)
    ready = reg('enrol', 'ready', challenge=offered['challenge'], acceptance=accepted['acceptance'])
    again = local('acceptResult', 'installed', result=ready['result'])
    assert again['profiles'] == installed['profiles']
    assert again['binding']['generation'] == installed['binding']['generation']+1
    assert floor.exists()
    retired = reg('revoke', 'retired', binding=again['binding'], reason='Reader-only slot reuse')
    local('acceptResult', 'retired', result=retired['result'])
    candidate_command = [str(w.c['suite']), 'authority-inspection', 'admission', 'candidate',
        '--directory', str(root/'ReaderOnly'), '--clock-witness',
        str(w.reader_clock/'ClockHealth.json'), '--json-stdin']
    description = reg('describe', 'descriptor')
    selected = local('prepare', 'prepared', bootstrap=description['bootstrap'],
        proof=description['proof'], expectedKey=description['currentKey'], roles=[0],
        minimumRoute=1 if w.assurance=='Independent' else 0)
    claim = (description['claimFloor']+1).to_bytes(8,'big').hex()+os.urandom(24).hex()
    request = hashlib.sha256(json.dumps(selected['roles'],sort_keys=True).encode()).hexdigest()
    offered = reg('challenge','challenge',claim=claim,requestDigest=request,
        roles=selected['roles'],applicationBinding=application)
    accepted = local('acceptChallenge','acceptance',challenge=offered['challenge'],
        applicationBinding=application,requestDigest=request,claim=claim)
    ready = reg('enrol','ready',challenge=offered['challenge'],acceptance=accepted['acceptance'])
    reader_only = local('acceptResult','installed',result=ready['result'])
    assert len(reader_only['profiles']) == 1 and reader_only['profiles'][0]['role'] == 0
    assert reader_only['profiles'][0].get('connectGrant') is None
    w.c['report']['cases'].append(dict(case='NativeAdmissionReaderOnlySubset',passed=True,
        advertisedRoles=[0,1],selectedRoles=[0],noApplicationGrant=True))
    spec['enabled'] = False
    w.write(path := root/'Policy.json', json.dumps(spec).encode())
    w.client('Administrator', ['authority-inspection', 'admission', 'policy'],
             ['--spec', w.put('Administrator', path)])
    retired = reg('revoke', 'retired', binding=reader_only['binding'], reason='Withdrawn policy cleanup')
    local('acceptResult', 'retired', result=retired['result'])
    # Adopt one explicitly owner-rostered existing manual profile after its actor stops.
    w.stop_agent()
    original_profile=json.loads((w.reader/'Profile.json').read_bytes())
    legacy_floor=w.reader/'Joined/Requester/AuthorityFloor.json'
    old_floor=json.loads(legacy_floor.read_bytes())
    legacy_registrar=Ed25519PrivateKey.generate()
    legacy_descriptor=Ed25519PrivateKey.generate()
    w.actor('LegacyRegistrar',legacy_registrar)
    spec.update(id=os.urandom(32).hex(),registrar=w.c['public_key'](legacy_registrar).hex(),
        descriptor=w.c['public_key'](legacy_descriptor).hex(),templates=[spec['templates'][1]],
        legacy=[w.recipient_member],enabled=True)
    w.write(path:=root/'LegacyPolicy.json',json.dumps(spec).encode())
    w.client('Administrator',['authority-inspection','admission','policy'],['--spec',w.put('Administrator',path)])
    config['policy']=spec['id']
    w.write(path:=root/'LegacyRegistrar.json',json.dumps(config).encode())
    configuration=w.put('LegacyRegistrar',path)
    base=w.client_args('LegacyRegistrar',['authority-inspection'])
    base=base[:base.index('authority-inspection')];base.insert(3,'--interactive')
    registrar_command=[*base,'authority-inspection','admission','registrar','--configuration',configuration,'--json-stdin']
    candidate_command=[str(w.c['suite']),'authority-inspection','admission','candidate','--directory',str(root/'LegacyCandidate'),
        '--clock-witness',str(w.reader_clock/'ClockHealth.json'),'--adopt-profile','1='+str(w.reader/'Profile.json'),'--json-stdin']
    description=reg('describe','descriptor')
    prepared=local('prepare','prepared',bootstrap=description['bootstrap'],proof=description['proof'],
        expectedKey=description['currentKey'],roles=[1],minimumRoute=1 if w.assurance=='Independent' else 0)
    assert prepared['roles'][0]['member']==w.join_request['devicePublicKey']
    claim=(description['claimFloor']+1).to_bytes(8,'big').hex()+os.urandom(24).hex()
    request=hashlib.sha256(json.dumps(prepared['roles'],sort_keys=True).encode()).hexdigest()
    offered=reg('challenge','challenge',claim=claim,requestDigest=request,roles=prepared['roles'],applicationBinding=application)
    acceptance=local('acceptChallenge','acceptance',challenge=offered['challenge'],applicationBinding=application,requestDigest=request,claim=claim)
    ready=reg('adopt','ready',challenge=offered['challenge'],acceptance=acceptance['acceptance'])
    migrated=local('acceptResult','installed',result=ready['result'])
    new_profile=json.loads((w.reader/'Profile.json').read_bytes())
    assert new_profile['device']==original_profile['device']
    assert new_profile['relayIdentity']==original_profile['relayIdentity']
    assert migrated['profiles'][0]['directory']==str(w.reader/'Joined')
    current_floor=json.loads(legacy_floor.read_bytes())
    assert current_floor['sequence']>old_floor['sequence']
    retired=reg('revoke','retired',binding=migrated['binding'],reason='Legacy migration checked')
    local('acceptResult','retired',result=retired['result'])
    spec['enabled']=False;w.write(path:=root/'LegacyPolicy.json',json.dumps(spec).encode())
    w.client('Administrator',['authority-inspection','admission','policy'],['--spec',w.put('Administrator',path)])
    w.c['report']['cases'].append(dict(case='NativeAdmissionLegacyAdoption',passed=True,sameKeys=True,sameFloor=True,policyWithdrawal=True))
    w.c['report']['cases'].append(dict(case='NativeAdmissionWorkflow', passed=True,
        sameKeys=True, retainedFloor=True, reusableCapacity=True, exactRetry=True,
        currentRenewalProof=True, withdrawal=True))
