"""Test-only authoritative fixture assets, never a production lock override."""
import hashlib
import json


def synthetic_assets():
    from p11lab.catalog import package_data
    from p11lab.tool_inputs import _canonical, _digest
    lock_name = 'tool-inputs/consumer.debian13-amd64.lock.json'
    lock = json.loads(package_data(lock_name).read_bytes())
    proof = json.loads(package_data(lock['provenance']['path']).read_bytes())
    payloads = {}
    def tiny(record, kind):
        data = ('synthetic ' + kind + ' ' + record['url']).encode()
        payloads[record['url']] = data
        record.update(size=len(data), sha256=hashlib.sha256(data).hexdigest())
    for package in lock['packages']:
        tiny(package, 'binary')
        package['path'] = 'binaries/' + package['sha256'] + '.deb'
    for source in lock['sources']:
        for record in source['files']:
            tiny(record, 'source')
            record['path'] = 'sources/' + record['sha256'] + '/' + record['filename']
    for record in lock['metadata']:
        tiny(record, 'metadata')
        for suite in ('trixie', 'trixie-updates', 'trixie-security'):
            entry = proof['metadata'][suite]
            for candidate in [entry] + entry['indexes']:
                if candidate['url'] == record['url']:
                    candidate.update(size=record['size'], sha256=record['sha256'])
    proof['source_bindings'] = [{k:s[k] for k in ('name','version','files','index','stanza_sha256')} for s in lock['sources']]
    proof['lock_binding_sha256'] = _digest(_canonical({k:v for k,v in lock.items() if k != 'provenance'}))
    raw = json.dumps(proof, sort_keys=True).encode()
    lock['provenance']['sha256'] = _digest(raw)
    return {lock_name: json.dumps(lock, sort_keys=True).encode(), lock['provenance']['path']: raw}, payloads


def install_assets(monkeypatch, assets):
    import p11lab.tool_inputs as module
    original = module.package_data
    class Asset:
        def __init__(self, raw): self.raw = raw
        def read_bytes(self): return self.raw
    monkeypatch.setattr(module, 'package_data', lambda name: Asset(assets[name]) if name in assets else original(name))


def fake_network(monkeypatch, payloads, *, fail_at=None):
    import io
    import p11lab.tool_downloads as module
    calls = []
    class Response(io.BytesIO):
        headers = {}
        def __init__(self, url):
            super().__init__(payloads[url]); self.url = url
        def geturl(self): return self.url
        def read1(self, count): return self.read(count)
    class Opener:
        def open(self, request, timeout):
            calls.append(request.full_url)
            if len(calls) == fail_at: raise OSError('synthetic acquisition failure')
            return Response(request.full_url)
    monkeypatch.setattr(module, 'build_opener', lambda *handlers: Opener())
    return calls
