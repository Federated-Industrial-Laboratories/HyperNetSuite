#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Demonstrate a fresh v2 authority check before each authorised echo effect."""
import argparse
import hashlib
import json
from hypernet_streams import Agent, AgentError, Disposition
from stream_service import header, principal


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--agent', required=True)
    sub = parser.add_subparsers(dest='command', required=True)
    service = sub.add_parser('serve')
    service.add_argument('--allow-principal', action='append', required=True)
    client = sub.add_parser('echo')
    client.add_argument('--service', required=True)
    client.add_argument('message')
    args = parser.parse_args()
    agent = Agent(args.agent, version=2)
    if args.command == 'echo':
        with agent.connect(args.service, 'example/1') as stream:
            header(stream, {'operation': 'echo', 'message': args.message})
            stream.shutdown_write()
            print(json.dumps({'response': header(stream), 'privacy': stream.privacy}))
        return
    print(json.dumps({'apiSupported': agent.capabilities().supported}), flush=True)
    while True:
        with agent.accept() as stream:
            try:
                if principal(stream.peer.get('principal')) not in args.allow_principal:
                    raise PermissionError('application caller is not allowed')
                request = header(stream)
                message = request.get('message')
                if set(request) != {'operation', 'message'} or request['operation'] != 'echo' or not isinstance(message, str) or len(message.encode('utf-8')) > 2048:
                    raise ValueError('unsupported or oversized echo request')
                canonical = json.dumps(request, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')
                result = agent.check_authority(stream, hashlib.sha256(canonical).digest())
                if result.disposition is Disposition.DENIED:
                    header(stream, {'ok': False, 'code': 'Denied'})
                elif not result.permitted:
                    header(stream, {'ok': False, 'code': result.disposition.value})
                else:
                    # Re-evaluate application policy and ordering here if either can change.
                    header(stream, {'ok': True, 'event': 'echo', 'message': message})
                stream.shutdown_write()
            except (AgentError, OSError, ValueError, EOFError) as error:
                print(json.dumps({'refused': type(error).__name__, 'connection': stream.id}), flush=True)


if __name__ == '__main__':
    main()
