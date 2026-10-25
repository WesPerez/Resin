#!/usr/bin/env python3
"""Hosted-only exact packaged-image preflight; synthetic DB, no real upstream."""
import base64
import hashlib
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
import tempfile
import time


def call(args, **kwargs):
    return subprocess.run(args, check=True, timeout=30, capture_output=True, **kwargs)


def check_packaged_fence(image, data, fixed):
    # Materialize only CI synthetic output in a private, disposable generation.
    # Never mount a real source writable and never send an activation POST here.
    with tempfile.TemporaryDirectory(prefix='resin-fenced-ci-') as root:
        root = Path(root)
        for kind in ('state', 'cache'):
            (root/kind).mkdir(mode=0o700)
        names = ('state/state.db', 'cache/cache.db', 'state/candidate-preflight.json')
        for name, body in zip(names, data):
            target = root/name
            target.write_bytes(body)
            target.chmod(0o600)
        fixed_args = ['docker', 'create', '--pull', 'never', '--network', 'none', '--read-only',
                      '--user', f'{os.getuid()}:{os.getgid()}', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
                      '--restart', 'no', '--log-driver', 'none', '--pids-limit', '128',
                      '--memory', '512m', '--memory-swap', '512m', '--cpus', '1', '--shm-size', '1m']
        for kind, dest in (('state','/var/lib/resin'), ('cache','/var/cache/resin')):
            fixed_args += ['--mount', f'type=bind,src={root/kind},dst={dest}']
        for path in ('/tmp', '/var/log/resin'):
            fixed_args += ['--tmpfs', f'{path}:rw,noexec,nosuid,size=1m']
        fixed_args += ['--env','RESIN_ADMIN_TOKEN=preflight-fixture','--env','RESIN_PROXY_TOKEN=preflight-fixture',
                       '--entrypoint','/usr/local/bin/resin', image]
        command = ['fenced', '--transfer-id', fixed['transfer_id'], '--marker-sha256', hashlib.sha256(data[2]).hexdigest(),
                   '--authority-listen', '127.0.0.1:29601', '--deadline', '20s']
        cid = call(fixed_args+command).stdout.decode().strip()
        try:
            call(['docker','start',cid])
            ready = None
            for _ in range(40):
                status = subprocess.run(['docker','exec',cid,'wget','-qO-','-T','1',
                                         '--header=Authorization: Bearer preflight-fixture',
                                         'http://127.0.0.1:29601/authority'],capture_output=True,timeout=3)
                if status.returncode == 0:
                    ready = json.loads(status.stdout)
                    break
                time.sleep(.1)
            info = json.loads(call(['docker','inspect',cid]).stdout)[0]
            assert info['Config']['User']==f'{os.getuid()}:{os.getgid()}'
            assert ready and ready['phase']=='fenced_ready', f"packaged fenced readiness absent (status={info['State']['Status']}, exit={info['State']['ExitCode']})"
            assert ready['candidate_sha']==os.environ['GITHUB_SHA']
            assert ready['transfer_id']==fixed['transfer_id'] and not ready['writes_may_have_started']
            assert not ready.get('activation_nonce')
            no_data = subprocess.run(['docker','exec',cid,'wget','-qO-','-T','1','http://127.0.0.1:2260/'],
                                     capture_output=True,timeout=3)
            assert no_data.returncode != 0, 'fenced constructor bound ordinary endpoint'
            call(['docker','kill','--signal','TERM',cid])
            call(['docker','wait',cid])
            info = json.loads(call(['docker','inspect',cid]).stdout)[0]
            assert not info['State']['Running'] and info['State']['ExitCode'] != 0
            record = json.loads((root/'state/candidate-authority.json').read_text())
            assert record['phase']=='failed' and not record['writes_may_have_started']
        finally:
            call(['docker','rm','--force',cid]) # exact CI-owned synthetic container only
        for name, body in zip(names, data):
            assert (root/name).read_bytes()==body
        for db in (root/'state/state.db',root/'cache/cache.db'):
            assert not any(Path(str(db)+suffix).exists() for suffix in ('-wal','-shm','-journal'))
        for args in (command, [], ['unknown-command']):
            cid = call(fixed_args+args).stdout.decode().strip()
            try:
                result = subprocess.run(['docker','start','--attach',cid],capture_output=True,timeout=10)
                assert result.returncode != 0, 'retained authority or unknown command bypassed'
            finally:
                call(['docker','rm','--force',cid])


def main():
    if os.environ.get('GITHUB_ACTIONS') != 'true':
        raise SystemExit('hosted-only fixture')
    image, fixture = sys.argv[1], Path(sys.argv[2]).resolve()
    fixed = json.loads((fixture/'fixture.json').read_text())
    before = {n:hashlib.sha256((fixture/n).read_bytes()).hexdigest() for n in ('state.db','cache.db')}
    call(['docker','pull',image])
    for bad in (False, True):
        args = ['docker','create','--pull','never','--network','none','--read-only','--user','0:0',
                '--cap-drop','ALL','--security-opt','no-new-privileges:true','--restart','no','--log-driver','none',
                '--pids-limit','128','--memory','512m','--memory-swap','512m','--cpus','1','--shm-size','1m',
                '--mount',f'type=bind,src={fixture},dst=/snapshot,readonly',
                '--tmpfs','/candidate-work:rw,noexec,nosuid,nodev,size=128m,mode=0700']
        for path,size in (('/tmp','16m'),('/var/lib/resin','1m'),('/var/cache/resin','1m'),('/var/log/resin','1m')):
            args += ['--tmpfs',f'{path}:rw,noexec,nosuid,size={size}']
        args += ['--env','RESIN_ADMIN_TOKEN=preflight-fixture','--env','RESIN_PROXY_TOKEN=preflight-fixture',
                 '--entrypoint','/usr/local/bin/resin',image,'preflight','--export-bundle',
                 '--transfer-id',fixed['transfer_id'],'--snapshot-dir','/snapshot','--output-dir','/candidate-work/generation',
                 '--state-sha256',fixed['state_sha256'],'--cache-sha256',fixed['cache_sha256'],
                 '--lease-sha256','0'*64 if bad else fixed['lease_digest'],'--lease-count',str(fixed['lease_count'])]
        cid=call(args).stdout.decode().strip()
        try:
            info=json.loads(call(['docker','inspect',cid]).stdout)[0]
            assert info['HostConfig']['NetworkMode']=='none'
            assert info['HostConfig']['Memory']==512*1024*1024
            assert info['HostConfig']['ShmSize']==1048576
            assert info['HostConfig']['Tmpfs']['/candidate-work']=='rw,noexec,nosuid,nodev,size=128m,mode=0700'
            assert all(m['Type'] in ('bind','tmpfs') for m in info['Mounts'])
            assert [m['Destination'] for m in info['Mounts'] if m['Type']=='bind']==['/snapshot']
            with tempfile.TemporaryFile() as out:
                def limit(): resource.setrlimit(resource.RLIMIT_FSIZE,(96*1024*1024,96*1024*1024))
                result=subprocess.run(['docker','start','--attach',cid],stdout=out,stderr=subprocess.DEVNULL,
                                      timeout=170,preexec_fn=limit)
                out.seek(0); raw=out.read(96*1024*1024)
            ended=json.loads(call(['docker','inspect',cid]).stdout)[0]
            assert not ended['State']['Running'] and not ended['State']['OOMKilled']
            if bad:
                assert result.returncode != 0 and ended['State']['ExitCode'] != 0
                continue
            assert result.returncode == 0 and ended['State']['ExitCode']==0
            bundle=json.loads(raw); receipt=bundle['receipt']
            assert bundle['version']=='resin-candidate-bundle/v1'
            assert receipt['candidate_sha']==os.environ['GITHUB_SHA']
            assert receipt['transfer_id']==fixed['transfer_id']
            assert receipt['lease_digest']==fixed['lease_digest'] and receipt['lease_count']==fixed['lease_count']
            assert receipt['authority_activated'] is False and receipt['outbound_validated'] is False
            assert len(receipt['effective_runtime_digest'])==len(receipt['effective_config_digest'])==64
            assert [f['name'] for f in bundle['files']]==['state/state.db','cache/cache.db','state/candidate-preflight.json']
            data=[base64.b64decode(f['data'],validate=True) for f in bundle['files']]
            for body,row in zip(data,receipt['candidate_databases']):
                assert len(body)==row['size'] and hashlib.sha256(body).hexdigest()==row['sha256']
            marker=json.loads(data[2]); assert marker['transfer_id']==receipt['transfer_id']
            assert marker['databases']==receipt['candidate_databases']
            assert marker['effective_runtime_digest']==receipt['effective_runtime_digest']
            assert marker['strong_logical_digest']==receipt['strong_logical_digest']
            assert marker['effective_config_digest']==receipt['effective_config_digest']
            check_packaged_fence(image,data,fixed)
        finally:
            # Only CI-owned synthetic containers, exact returned ID.
            call(['docker','rm','--force',cid])
    assert before=={n:hashlib.sha256((fixture/n).read_bytes()).hexdigest() for n in before}
    print(json.dumps({'packaged_preflight':'passed','packaged_fenced_start':'passed','synthetic_fixture':True,'source_unchanged':True,'authority_activated':False}))


if __name__=='__main__': main()
