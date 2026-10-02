"""Owned direct/provider lifecycle. Future transports use the same RunResult."""
from dataclasses import asdict
from pathlib import Path
import re
import os
import shutil
import signal
import tempfile
import threading
import time
from uuid import uuid4

from .catalog import load_environment
from .docker import Docker, DockerError
from .models import RunSpec, RunResult
from .receipts import write_receipt


def _validate(spec):
    descriptor = load_environment(spec.environment, spec.channel)
    if descriptor['channel_spec']['status'] != 'locked':
        raise ValueError('run requires an implemented locked provider channel')
    if spec.mode != 'direct' or spec.execution_location != 'provider':
        raise ValueError('only direct/provider execution is available')
    if spec.consumer_artifact is not None or spec.client_artifact is not None:
        raise ValueError('direct/provider cannot use separate consumer/client artifacts; select a derivative via artifact')
    artifact = spec.artifact
    if (artifact.kind != 'docker-local' or not re.fullmatch(r'sha256:[0-9a-f]{64}', artifact.reference)
            or artifact.sha256 != artifact.reference.removeprefix('sha256:')
            or artifact.platform not in descriptor['runtime_platforms']):
        raise ValueError('direct/provider requires an exact supported docker-local engine image ID')
    if not spec.argv or any(not isinstance(a, str) or '\0' in a for a in spec.argv):
        raise ValueError('application requires literal argv without NUL bytes')
    if spec.timeout_seconds <= 0 or not spec.cwd.is_dir():
        raise ValueError('positive timeout and existing caller cwd are required')
    unknown = set(spec.inputs) - set(descriptor['inputs']) - {'P11LAB_STATE_DIR'}
    if unknown or any(not isinstance(v, str) or '\n' in v or '\r' in v or '\0' in v for v in spec.inputs.values()):
        raise ValueError('inputs must be allowlisted single-line strings')
    for key, value in spec.inputs.items():
        if key.endswith('_FILE') and not Path(value).is_file():
            raise ValueError('credential input file must be readable')
        if key == 'P11LAB_STATE_DIR' and not Path(value).is_dir():
            raise ValueError('explicit persistent state directory must already exist')
    if spec.output_dir.exists():
        raise ValueError('output directory must be a fresh attempt directory')
    for key in spec.inputs:
        if key.endswith('_FILE') and key.removesuffix('_FILE') in spec.inputs:
            raise ValueError('conflicting scalar/file credential inputs')
    return descriptor


def run_application(spec: RunSpec) -> RunResult:
    descriptor = _validate(spec)
    engine = Docker()
    observed = engine.image(spec.artifact)  # no resource created before preflight
    output = spec.output_dir.resolve()
    cwd = spec.cwd.resolve()
    if any(',' in str(path) for path in (output, cwd)):
        raise ValueError('Docker bind mount paths cannot contain commas')
    output.mkdir(parents=True)
    run_id, attempt_id = uuid4().hex, uuid4().hex
    labels = {'org.p11lab.run': run_id, 'org.p11lab.attempt': attempt_id}
    owned = []
    uncertain = []
    lifecycle, cleanup, stages = [], [], []
    app_returncode = None
    timed_out = False
    interrupted_signal = None
    deadline = time.monotonic() + spec.timeout_seconds
    old_handlers = {}

    def receive(signum, frame):
        nonlocal interrupted_signal
        interrupted_signal = interrupted_signal or signum

    if threading.current_thread() is threading.main_thread():
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            old_handlers[sig] = signal.signal(sig, receive)
    secrets = []
    state_directory = None
    state_ownership = None
    try:
        with tempfile.TemporaryDirectory(prefix='p11lab-input-') as private:
            envfile = Path(private) / 'environment'
            inputs = {}
            mounts = []
            for key, value in spec.inputs.items():
                if key == 'P11LAB_STATE_DIR':
                    continue
                if descriptor['inputs'][key]['secret']:
                    if key.endswith('_FILE'):
                        source = Path(value).resolve(strict=True)
                        with source.open('rb') as stream:
                            secret = stream.read(4097)
                        if len(secret) > 4096:
                            raise ValueError('credential input exceeds 4096-byte bound')
                        destination = '/run/p11lab-input/' + key
                        if ',' in str(source):
                            raise ValueError('Docker bind mount paths cannot contain commas')
                        snapshot = Path(private) / key
                        snapshot.write_bytes(secret)
                        snapshot.chmod(0o444)  # parent is 0700; only this file is mounted
                        mounts.extend(['--mount', f'type=bind,src={snapshot},dst={destination},readonly'])
                        inputs[key] = destination
                    else:
                        secret = value.encode()
                        inputs[key] = value
                    if secret:
                        secrets.append(secret.decode('utf-8', 'replace'))
                else:
                    inputs[key] = value
            envfile.write_text(''.join(f'{k}={v}\n' for k, v in inputs.items()))
            envfile.chmod(0o600)
            if 'P11LAB_STATE_DIR' in spec.inputs:
                state = Path(spec.inputs['P11LAB_STATE_DIR']).resolve()
                if ',' in str(state):
                    raise ValueError('Docker bind mount paths cannot contain commas')
                state_ownership = {'uid': state.stat().st_uid, 'gid': state.stat().st_gid,
                                   'mode': oct(state.stat().st_mode & 0o777)}
                state_mount = f'type=bind,src={state},dst=/var/lib/p11lab'
            else:
                state_directory = Path(tempfile.mkdtemp(prefix='p11lab-state-'))
                state_ownership = {'uid': state_directory.stat().st_uid, 'gid': state_directory.stat().st_gid,
                                   'mode': oct(state_directory.stat().st_mode & 0o777)}
                state = engine.volume('p11lab-' + run_id, labels, state_directory)
                owned.append(('volume', state))
                state_mount = f'type=volume,src={state},dst=/var/lib/p11lab,volume-nocopy'
            options = ['--user', f'{os.getuid()}:{os.getgid()}', '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                       '--tmpfs', f'/run/p11lab:rw,nosuid,nodev,uid={os.getuid()},gid={os.getgid()},mode=0700', '--tmpfs', '/tmp:rw,nosuid,nodev',
                       '--mount', state_mount, '--env-file', str(envfile), *mounts]
            for index, argv in enumerate((('init',), ('health',), ('exec', '--', *spec.argv), ('health',))):
                phase = ('init', 'ready', 'application', 'post-health')[index]
                if interrupted_signal or time.monotonic() >= deadline:
                    timed_out = not bool(interrupted_signal)
                    lifecycle.append('interrupted' if interrupted_signal else 'timeout')
                    break
                stage_options = list(options)
                if phase == 'application':
                    stage_options.extend(['--mount', f'type=bind,src={cwd},dst=/workspace',
                                          '--mount', f'type=bind,src={output},dst=/p11lab-output',
                                          '--workdir', '/workspace', '--env', 'P11LAB_OUTPUT_DIR=/p11lab-output'])
                identity = engine.create(spec.artifact.reference, argv, stage_options, labels, 'p11lab-' + run_id + '-' + str(index))
                owned.append(('container', identity))
                result = engine.execute(identity, max(.01, deadline - time.monotonic()), lambda: interrupted_signal)
                timed_out = timed_out or result.timed_out
                def redact(text, truncated):
                    if truncated and secrets:
                        # Drop the boundary where a retained prefix could end
                        # halfway through a credential before value redaction.
                        trim = max(len(secret) for secret in secrets) - 1
                        if trim:
                            text = text[:-trim]
                    for secret in sorted(secrets, key=len, reverse=True):
                        text = text.replace(secret, '[REDACTED]')
                    return text
                (output / (phase + '.stdout.log')).write_text(redact(result.stdout, result.stdout_truncated))
                (output / (phase + '.stderr.log')).write_text(redact(result.stderr, result.stderr_truncated))
                stages.append({'phase': phase, 'container_id': identity, 'returncode': result.returncode,
                               'timed_out': result.timed_out, 'stdout_truncated': result.stdout_truncated,
                               'stderr_truncated': result.stderr_truncated})
                if phase == 'application':
                    app_returncode = result.returncode
                elif result.returncode:
                    lifecycle.append(phase + ' failed')
                    break
                if result.timed_out or interrupted_signal:
                    break
    except (DockerError, OSError, ValueError) as error:
        # Do not expose subprocess arguments, environment or credential paths.
        if isinstance(error, DockerError):
            if error.resource is not None:
                owned.append(error.resource)
            if error.uncertain_resource is not None:
                uncertain.append(error.uncertain_resource)
                cleanup.append('creation status unknown: ' + ' '.join(error.uncertain_resource))
        lifecycle.append('runner operation failed (' + type(error).__name__ + ')')
    finally:
        for kind, identity in reversed(owned):
            try:
                engine.remove(kind, identity, labels)
            except (DockerError, OSError, ValueError):
                cleanup.append(kind + ' cleanup failed: ' + identity)
        if state_directory is not None and not cleanup:
            try:
                shutil.rmtree(state_directory)
            except OSError:
                cleanup.append('private state directory cleanup failed')
        for sig, handler in old_handlers.items():
            signal.signal(sig, handler)
    exit_code = (128 + interrupted_signal if interrupted_signal else 124 if timed_out else
                 app_returncode if app_returncode else 1 if lifecycle or cleanup else 0)
    receipt_path = output / 'receipt.json'
    record = {'schema_version': 1, 'run_id': run_id, 'attempt_id': attempt_id,
              'environment': spec.environment, 'channel': spec.channel, 'mode': spec.mode,
              'execution_location': spec.execution_location,
              'artifacts': {'provider': asdict(spec.artifact), 'consumer': None, 'client': None},
              'image_observation': {'Id': observed['Id'], 'Descriptor': observed.get('Descriptor'),
                                    'platform': spec.artifact.platform},
              'execution': {'container_cwd': '/workspace', 'output_mount': '/p11lab-output',
                            'uid_gid': f'{os.getuid()}:{os.getgid()}',
                            'capabilities': [], 'network': 'none', 'root_readonly': True,
                            'writable': ['/var/lib/p11lab', '/run/p11lab', '/tmp', '/workspace', '/p11lab-output'],
                            'argv_count': len(spec.argv)},
              'inputs': {key: {'present': True, 'secret': descriptor['inputs'][key]['secret']}
                         for key in spec.inputs if key != 'P11LAB_STATE_DIR'},
              'state': {'persistent_caller_directory': 'P11LAB_STATE_DIR' in spec.inputs,
                        'owned_directory': str(state_directory) if state_directory else None,
                        'directory_ownership': state_ownership,
                        'control_uid_gid': f'{os.getuid()}:{os.getgid()}', 'control_mode': '0700',
                        'owned_directory_retained': state_directory.exists() if state_directory else False},
              'stages': stages, 'owned_resources': [{'kind': k, 'identity': i} for k, i in owned],
              'uncertain_resources': [{'kind': k, 'name': n} for k, n in uncertain],
              'app_returncode': app_returncode, 'lifecycle_errors': lifecycle, 'cleanup_errors': cleanup,
              'exit_code': exit_code, 'timeout': timed_out, 'interrupted_signal': interrupted_signal}
    write_receipt(receipt_path, record)
    return RunResult(app_returncode, tuple(lifecycle), tuple(cleanup), exit_code, receipt_path)
