"""Installed support with source checkout reads actively denied, not just unused."""
import base64
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import zipfile

import pytest

from tool_input_fixtures import synthetic_assets


GUARD = r'''
import io, json, os, sys
from pathlib import Path
config = json.loads(Path(sys.argv[1]).read_text())
blocked = config['blocked']
def audit(event, args):
    if event in {'open', 'os.listdir', 'os.scandir', 'os.chdir'} and args and isinstance(args[0], (str, bytes)):
        path = os.path.abspath(os.fsdecode(args[0]))
        if any(path == root or path.startswith(root + os.sep) for root in blocked):
            raise PermissionError('checkout access denied by installed-test guard')
    if event == 'subprocess.Popen':
        raise PermissionError('installed tool resolver must not execute host helpers')
sys.addaudithook(audit)
import p11lab
from p11lab.cli import main
import p11lab.tool_inputs as inputs
import p11lab.tool_downloads as downloads
assert Path(p11lab.__file__).is_relative_to(Path(sys.prefix))
try:
    open(blocked[0] + '/AGENTS.md', 'rb')
except PermissionError:
    pass
else:
    raise AssertionError('checkout denial guard did not fire')
mode = config['mode']
if mode == 'catalog':
    assert len(inputs.load_tool_input_lock('consumer', target='debian13-amd64')['packages']) == 43
    print('installed-authority-ok')
elif mode == 'invalid-validate':
    path = Path(p11lab.__file__).parent/'data/tool-inputs/consumer.debian13-amd64.lock.json'
    original = path.read_bytes()
    try:
        data = json.loads(original); data['packages'][0]['sha256'] = '0'*64
        path.write_text(json.dumps(data))
        assert main(['validate']) == 2, 'validate ignored a corrupt installed tool lock'
    finally:
        path.write_bytes(original)
    print('invalid-lock-rejected')
else:
    payloads = {k: base64.b64decode(v) for k,v in config['payloads'].items()}
    requests = []
    class Response(io.BytesIO):
        headers = {}
        def __init__(self, url):
            data = payloads[url]
            if mode == 'bad-hash': data = b'X'*len(data)
            super().__init__(data); self.url = url
        def geturl(self): return self.url
        def read1(self, count): return self.read(count)
    def opener(handler, *other_handlers):
        class Opener:
            def open(self, request, timeout):
                requests.append(request.full_url)
                if mode == 'redirect':
                    request = handler.redirect_request(request, None, 302, 'Found', {}, 'https://forbidden.invalid/input')
                    requests.append(request.full_url)
                return Response(request.full_url)
        return Opener()
    downloads.build_opener = opener
    output = Path(config['output'])
    resource = Path(p11lab.__file__).parent/'data/consumer/smoke.c'
    original = resource.read_bytes()
    try:
        if mode == 'missing-resource': resource.unlink()
        status = main(['tools','resolve','consumer','--target','debian13-amd64','--output-dir',str(output)])
    finally:
        if mode == 'missing-resource': resource.write_bytes(original)
    if mode in {'bad-hash','redirect','missing-resource'}:
        assert status == 2
        assert not (output/'resolved-inputs.json').exists()
        if mode == 'redirect': assert len(requests) == 1
        if mode == 'missing-resource': assert not requests
    else:
        assert status == 0
        result = inputs.verify_resolved_tool_inputs('consumer',target='debian13-amd64',receipt_path=output/'resolved-inputs.json')
        assert result['admission'] == 'unreviewed' and 'artifact' not in result
        assert len(result['records']) == 108 and len(requests) == 100
        if mode == 'forgery':
            result['records'][0]['sha256'] = '0'*64
            (output/'resolved-inputs.json').write_text(json.dumps(result))
            try:
                inputs.verify_resolved_tool_inputs('consumer',target='debian13-amd64',receipt_path=output/'resolved-inputs.json')
            except ValueError:
                pass
            else: raise AssertionError('forged receipt accepted')
'''.replace('import io, json, os, sys', 'import base64, io, json, os, sys')


@pytest.fixture(scope='module')
def installed_tools(tmp_path_factory):
    root = tmp_path_factory.mktemp('installed tools no checkout with spaces')
    checkout = Path(__file__).resolve().parents[1]
    wheels = root/'wheels'
    env = {k:v for k,v in os.environ.items() if k not in {'PYTHONPATH', 'PYTHONHOME'}}
    env['UV_CACHE_DIR'] = str(root/'uv-cache')
    subprocess.run(['uv','build','--wheel','--offline','--no-build-isolation','--python',sys.executable,
                    '--out-dir',str(wheels),str(checkout)], check=True, capture_output=True, text=True, env=env)
    wheel = next(wheels.glob('*.whl'))
    assets, payloads = synthetic_assets()
    fixture_dir = root/'fixture wheel'; fixture_dir.mkdir()
    fixture_wheel = fixture_dir/wheel.name
    with zipfile.ZipFile(wheel) as archive:
        entries = {name:archive.read(name) for name in archive.namelist()}
    for name, data in assets.items(): entries['p11lab/data/'+name] = data
    record_name = next(name for name in entries if name.endswith('.dist-info/RECORD'))
    record = io.StringIO()
    writer = csv.writer(record, lineterminator='\n')
    for name, data in entries.items():
        if name != record_name:
            digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip('=')
            writer.writerow([name, 'sha256='+digest, len(data)])
    writer.writerow([record_name,'','']); entries[record_name] = record.getvalue().encode()
    with zipfile.ZipFile(fixture_wheel,'w',zipfile.ZIP_DEFLATED) as archive:
        for name,data in entries.items(): archive.writestr(name,data)
    pythons = {}
    for kind, selected in [('real',wheel), ('fixture',fixture_wheel)]:
        venv = root/(kind+' venv')
        subprocess.run(['uv','venv','--offline','--python',sys.executable,str(venv)],check=True,capture_output=True,text=True,env=env)
        python = venv/('Scripts/python.exe' if os.name=='nt' else 'bin/python')
        subprocess.run(['uv','pip','install','--offline','--no-deps','--python',str(python),str(selected)],check=True,capture_output=True,text=True,env=env)
        pythons[kind] = python
    caller = root/'caller without checkout'; caller.mkdir()
    script = caller/'guard.py'; script.write_text(GUARD)
    # A linked worktree sits below the shared repo; deny both paths, including
    # any absolute fallback to the original root or its artifact cache.
    shared = subprocess.check_output(['git','rev-parse','--git-common-dir'],cwd=checkout,text=True).strip()
    repo_root = Path(shared).resolve().parent
    blocked = sorted({str(checkout),str(repo_root)})
    return root, caller, script, env, pythons, blocked, payloads


def run_installed(installed_tools, mode, kind='fixture'):
    root, caller, script, env, pythons, blocked, payloads = installed_tools
    config = caller/(mode+'.json')
    config.write_text(json.dumps({'mode':mode, 'blocked':blocked, 'output':str(root/('output '+mode)),
                                 'payloads':{k:base64.b64encode(v).decode() for k,v in payloads.items()}}))
    # No development executables or PYTHONPATH. The guard also forbids spawning
    # any host helper, so an accidental dpkg/git/subprocess fallback fails.
    env = env | {'PATH':os.defpath}
    result = subprocess.run([str(pythons[kind]),'-I',str(script),str(config)],cwd=caller,env=env,capture_output=True,text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    return result


def test_production_installed_authority_works_without_checkout(installed_tools):
    assert 'installed-authority-ok' in run_installed(installed_tools,'catalog','real').stdout


def test_installed_validate_rejects_corrupt_tool_lock(installed_tools):
    assert 'invalid-lock-rejected' in run_installed(installed_tools,'invalid-validate','real').stdout


@pytest.mark.parametrize('mode',['success','bad-hash','redirect','missing-resource','forgery'])
def test_installed_resolve_and_failures_with_synthetic_authority(installed_tools,mode):
    run_installed(installed_tools,mode)
