"""Narrow deterministic checks for the p11scope demonstration.

Covers only what is cheap without network or Docker: the frozen pin
shape, example wiring (README links, vessel pin, CLI refusals), the
hash-verify refusal cases, and regression probes for the phase-1
doctor validation, the RESULT/chown ordering, and the docker-build
argv quoting. The probes stub curl/sha256sum/chown/docker on PATH and
drive the real scripts; bundle fetch, preflight, and live capture stay
in run.sh with its own retained evidence.
"""
import hashlib
import os
import re
import stat
import subprocess
import tarfile
from pathlib import Path


EXAMPLE = Path(__file__).resolve().parent.parent / 'examples' / 'p11scope'
LIB = EXAMPLE / 'lib.sh'
RUN = EXAMPLE / 'run.sh'
PINS = EXAMPLE / 'pins.env'


def read_pins():
    script = (f". '{PINS}' && printf '%s\\n' \"$P11SCOPE_VERSION\" "
              f"\"$P11SCOPE_TAG_OBJECT\" \"$P11SCOPE_REV\" "
              f"\"$P11SCOPE_BUNDLE_URL\" \"$P11SCOPE_BUNDLE_SHA256\"")
    proc = subprocess.run(['sh', '-c', script], capture_output=True,
                          text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.splitlines()


def test_pins_shape_and_consistency():
    version, tag_object, rev, url, digest = read_pins()
    assert re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version), version
    assert re.fullmatch(r'[0-9a-f]{40}', tag_object), tag_object
    assert re.fullmatch(r'[0-9a-f]{40}', rev), rev
    assert re.fullmatch(r'[0-9a-f]{64}', digest), digest
    expect = (f'https://github.com/mingulov/p11scope/releases/download/'
              f'v{version}/p11scope-{version}-x86_64-linux-musl.tar.gz')
    assert url == expect, url


def test_readme_relative_links_resolve():
    text = (EXAMPLE / 'README.md').read_text()
    targets = re.findall(r'\]\(([^)#]+)(?:#[^)]*)?\)', text)
    relative = [t for t in targets
                if not re.match(r'[a-zA-Z][a-zA-Z0-9+.-]*:', t)]
    assert relative, 'README has no relative links to check'
    for target in relative:
        assert (EXAMPLE / target).exists(), target


def test_vessel_base_is_digest_pinned():
    dockerfile = (EXAMPLE / 'Dockerfile.demo').read_text()
    match = re.search(r'^FROM debian:13\.6-slim@sha256:([0-9a-f]{64})$',
                      dockerfile, re.MULTILINE)
    assert match, 'vessel base must pin the debian digest'


def test_run_help_lists_inputs():
    proc = subprocess.run([str(RUN), '--help'], capture_output=True,
                          text=True, timeout=60)
    assert proc.returncode == 0
    for flag in ('--output-dir', '--privileged', '--tag', '--rebuild'):
        assert flag in proc.stdout


def test_run_refuses_missing_output_dir(tmp_path):
    proc = subprocess.run([str(RUN)], capture_output=True, text=True,
                          timeout=60, cwd=tmp_path)
    assert proc.returncode == 2
    assert 'refused: --output-dir is required' in proc.stderr


def test_run_refuses_existing_output_dir(tmp_path):
    out = tmp_path / 'out'
    out.mkdir()
    proc = subprocess.run([str(RUN), '--output-dir', str(out)],
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 2
    assert 'refused: output dir already exists' in proc.stderr


def test_run_refuses_unknown_argument(tmp_path):
    proc = subprocess.run([str(RUN), '--bogus', 'x'], capture_output=True,
                          text=True, timeout=60, cwd=tmp_path)
    assert proc.returncode == 2
    assert 'refused: unknown argument' in proc.stderr


def guard_call(function, *args):
    quoted = ' '.join(f"'{a}'" for a in args)
    return subprocess.run(['sh', '-c', f". '{LIB}'; {function} {quoted}"],
                          capture_output=True, text=True, timeout=60)


def test_verify_sha256_happy_path(tmp_path):
    target = tmp_path / 'file.bin'
    target.write_bytes(b'pinned-bytes')
    digest = hashlib.sha256(b'pinned-bytes').hexdigest()
    proc = guard_call('verify_sha256', str(target), digest)
    assert proc.returncode == 0, proc.stderr


def test_verify_sha256_refuses_mismatch(tmp_path):
    target = tmp_path / 'file.bin'
    target.write_bytes(b'other-bytes')
    proc = guard_call('verify_sha256', str(target), '0' * 64)
    assert proc.returncode == 1
    assert 'refused: sha256 mismatch' in proc.stderr


def test_verify_sha256_refuses_bad_shapes(tmp_path):
    target = tmp_path / 'file.bin'
    target.write_bytes(b'x')
    proc = guard_call('verify_sha256', str(target), 'zz')
    assert proc.returncode == 1
    assert 'refused: expected sha256 is not hex' in proc.stderr
    proc = guard_call('verify_sha256', str(tmp_path / 'missing'), '0' * 64)
    assert proc.returncode == 1
    assert 'refused: not a regular file' in proc.stderr


def test_pinned_bundle_hash_is_plausible():
    _, _, _, _, digest = read_pins()
    assert digest != '0' * 64


TIER_LINE = 'capability tier: T0 offline (target unassessed)'


def write_executable(path, content):
    path.write_text(content)
    path.chmod(0o755)


def write_p11scope_stub(path, version, doctor, extra):
    """Write a stub p11scope binary; each stage is (stdout, exit-code).

    An exit-code of 'SEGV' kills the stub with SIGSEGV after printing,
    mimicking a crashing doctor.
    """
    def emit(stage, text, code):
        lines = [f'    # {stage}']
        if text:
            lines.append(f"    printf '%s\\n' '{text}'")
        if code == 'SEGV':
            lines.append('    kill -SEGV $$')
        else:
            lines.append(f'    exit {code}')
        return '\n'.join(lines)

    path.write_text('#!/bin/sh\n'
                    'if [ "$1" = "--version" ]; then\n'
                    f'{emit("version", *version)}\n'
                    'fi\n'
                    'if [ "$1" = "doctor" ] && [ "$2" = "--extra-strict" ]; then\n'
                    f'{emit("extra-strict", *extra)}\n'
                    'fi\n'
                    'if [ "$1" = "doctor" ]; then\n'
                    f'{emit("doctor", *doctor)}\n'
                    'fi\n'
                    'echo "stub: unexpected argv $*" >&2\n'
                    'exit 127\n')
    path.chmod(0o755)


def make_stub_bundle(tmp_path, stub):
    """Pack a bundle-shaped tarball around a stub p11scope binary."""
    top = tmp_path / 'fake-bundle-top'
    top.mkdir()
    (top / 'p11scope').write_bytes(stub.read_bytes())
    (top / 'p11scope').chmod(0o755)
    (top / 'LICENSE').write_text('stub license')
    (top / 'RELEASE.json').write_text('{}')
    tarball = tmp_path / 'stub-bundle.tar.gz'
    with tarfile.open(tarball, 'w:gz') as archive:
        archive.add(top, arcname=top.name)
    return tarball


def make_phase1_stubs(tmp_path, stub):
    """PATH stubs letting run.sh phase 1 run hermetically (no network).

    The curl stub serves a bundle built around STUB; the sha256sum stub
    answers the pinned digest for any file.
    """
    _, _, _, _, digest = read_pins()
    tarball = make_stub_bundle(tmp_path, stub)
    bindir = tmp_path / 'stubbin'
    bindir.mkdir()
    write_executable(bindir / 'curl',
                     '#!/bin/sh\n'
                     'out=\n'
                     'prev=\n'
                     'for a in "$@"; do\n'
                     '  if [ "$prev" = "-o" ]; then out=$a; fi\n'
                     '  prev=$a\n'
                     'done\n'
                     'cp "$STUB_TARBALL" "$out"\n')
    write_executable(bindir / 'sha256sum',
                     '#!/bin/sh\n'
                     "printf '%s  %s\\n' \"$STUB_SHA256\" \"$1\"\n")
    env = dict(os.environ)
    env['PATH'] = f'{bindir}{os.pathsep}{env["PATH"]}'
    env['STUB_TARBALL'] = str(tarball)
    env['STUB_SHA256'] = digest
    return env


GOOD_VERSION = ('p11scope 0.2.0', 0)


def run_phase1(tmp_path, stub):
    env = make_phase1_stubs(tmp_path, stub)
    out = tmp_path / 'phase1-out'
    proc = subprocess.run([str(RUN), '--output-dir', str(out)],
                          capture_output=True, text=True, timeout=120,
                          env=env)
    return proc, out


def test_phase1_accepts_healthy_doctor_reports(tmp_path):
    """A T0-style stub (rc 1, tier verdicts) still completes phase 1."""
    stub = tmp_path / 'p11scope'
    write_p11scope_stub(stub, GOOD_VERSION,
                        (TIER_LINE, 1), (TIER_LINE, 1))
    proc, out = run_phase1(tmp_path, stub)
    assert proc.returncode == 0, proc.stderr
    assert 'P11SCOPE_DEMO_OK' in proc.stdout
    assert (out / 'work' / 'PHASE1').read_text() == 'PHASE1_DONE\n'
    assert (out / 'work' / 'tier.txt').read_text().strip() == TIER_LINE


def test_phase1_accepts_clean_doctor_reports(tmp_path):
    """A T1-style stub (rc 0, tier verdicts) completes phase 1 too."""
    stub = tmp_path / 'p11scope'
    write_p11scope_stub(stub, GOOD_VERSION,
                        (TIER_LINE, 0), (TIER_LINE, 0))
    proc, _ = run_phase1(tmp_path, stub)
    assert proc.returncode == 0, proc.stderr
    assert 'P11SCOPE_DEMO_OK' in proc.stdout


def assert_phase1_refused(proc, out):
    assert proc.returncode == 2, proc.stdout
    assert 'refused:' in proc.stderr
    assert 'P11SCOPE_DEMO_OK' not in proc.stdout
    assert not (out / 'work' / 'PHASE1').exists()


def test_phase1_refuses_crashing_doctor(tmp_path):
    """A doctor that dies by signal must refuse, never report OK."""
    stub = tmp_path / 'p11scope'
    write_p11scope_stub(stub, GOOD_VERSION,
                        ('partial table, no verdict', 'SEGV'),
                        (TIER_LINE, 1))
    proc, out = run_phase1(tmp_path, stub)
    assert_phase1_refused(proc, out)
    assert 'did not complete' in proc.stderr


def test_phase1_refuses_doctor_without_tier_verdict(tmp_path):
    """rc 1 alone is not a verdict: a missing tier line must refuse."""
    stub = tmp_path / 'p11scope'
    write_p11scope_stub(stub, GOOD_VERSION,
                        ('all probes skipped, no summary', 1),
                        (TIER_LINE, 1))
    proc, out = run_phase1(tmp_path, stub)
    assert_phase1_refused(proc, out)
    assert 'no capability-tier verdict' in proc.stderr


def test_phase1_refuses_insane_doctor_rc(tmp_path):
    """A tier line with an impossible rc (usage error) must refuse."""
    stub = tmp_path / 'p11scope'
    write_p11scope_stub(stub, GOOD_VERSION,
                        (TIER_LINE, 3), (TIER_LINE, 1))
    proc, out = run_phase1(tmp_path, stub)
    assert_phase1_refused(proc, out)
    assert 'did not complete' in proc.stderr


def test_phase1_refuses_crashing_extra_strict(tmp_path):
    """The extra-strict leg is validated too, not just plain doctor."""
    stub = tmp_path / 'p11scope'
    write_p11scope_stub(stub, GOOD_VERSION,
                        (TIER_LINE, 1), ('', 'SEGV'))
    proc, out = run_phase1(tmp_path, stub)
    assert_phase1_refused(proc, out)
    assert 'did not complete' in proc.stderr


def test_phase1_refuses_wrong_version_output(tmp_path):
    """--version printing something unexpected must refuse."""
    stub = tmp_path / 'p11scope'
    write_p11scope_stub(stub, ('not-p11scope 9.9.9', 0),
                        (TIER_LINE, 1), (TIER_LINE, 1))
    proc, out = run_phase1(tmp_path, stub)
    assert_phase1_refused(proc, out)
    assert '--version' in proc.stderr


def test_phase1_refuses_failing_version(tmp_path):
    """--version exiting nonzero must refuse."""
    stub = tmp_path / 'p11scope'
    write_p11scope_stub(stub, ('', 1),
                        (TIER_LINE, 1), (TIER_LINE, 1))
    proc, out = run_phase1(tmp_path, stub)
    assert_phase1_refused(proc, out)
    assert '--version' in proc.stderr


def run_lib_function(env, function, *args):
    quoted = ' '.join(f"'{a}'" for a in args)
    return subprocess.run(['sh', '-c', f". '{LIB}'; {function} {quoted}"],
                          capture_output=True, text=True, timeout=60,
                          env=env)


def assert_finalize_result_exists():
    probe = subprocess.run(['sh', '-c', f". '{LIB}' && command -v finalize_result"],
                           capture_output=True, text=True, timeout=60)
    assert probe.returncode == 0, 'lib.sh must define finalize_result'
    assert probe.stdout.strip() == 'finalize_result'


def test_finalize_result_refuses_unusable_owner(tmp_path):
    """A failing chown (bad uid) leaves no success marker behind."""
    assert_finalize_result_exists()
    work = tmp_path / 'work'
    work.mkdir()
    (work / 'evidence.txt').write_text('x')
    proc = run_lib_function(dict(os.environ), 'finalize_result',
                            str(work / 'RESULT'), 'P11SCOPE_DEMO_OK',
                            str(work), 'no-such-user-xyz', 'no-such-group-xyz')
    assert proc.returncode != 0
    assert not (work / 'RESULT').exists()


def test_finalize_result_orders_chown_before_marker(tmp_path):
    """Ownership first, marker last: the marker appears between the two
    chown calls, and the tree chown precedes the marker chown."""
    work = tmp_path / 'work'
    work.mkdir()
    result = work / 'RESULT'
    bindir = tmp_path / 'stubbin'
    bindir.mkdir()
    calls = bindir / 'chown-calls.log'
    write_executable(
        bindir / 'chown',
        '#!/bin/sh\n'
        f'if [ -e "{result}" ]; then seen=yes; else seen=no; fi\n'
        'printf \'<%s> marker=%s\\n\' "$*" "$seen" >>'
        f'"{calls}"\n'
        'exit 0\n')
    env = dict(os.environ)
    env['PATH'] = f'{bindir}{os.pathsep}{env["PATH"]}'
    proc = run_lib_function(env, 'finalize_result', str(result),
                            'P11SCOPE_DEMO_OK', str(work), '0', '0')
    assert proc.returncode == 0, proc.stderr
    assert result.read_text() == 'P11SCOPE_DEMO_OK\n'
    first, second = calls.read_text().splitlines()
    assert first == f'<-R 0:0 {work}> marker=no'
    assert second == f'<0:0 {result}> marker=yes'


def test_finalize_result_removes_marker_when_final_chown_fails(tmp_path):
    """If the marker's own chown fails, the marker is withdrawn."""
    assert_finalize_result_exists()
    work = tmp_path / 'work'
    work.mkdir()
    result = work / 'RESULT'
    bindir = tmp_path / 'stubbin'
    bindir.mkdir()
    write_executable(
        bindir / 'chown',
        '#!/bin/sh\n'
        'count_file="$STUB_CHOWN_COUNT"\n'
        'n=$(cat "$count_file" 2>/dev/null || echo 0)\n'
        'n=$((n + 1))\n'
        'printf "%s" "$n" >"$count_file"\n'
        'if [ "$n" = "1" ]; then exit 0; fi\n'
        'exit 1\n')
    env = dict(os.environ)
    env['PATH'] = f'{bindir}{os.pathsep}{env["PATH"]}'
    env['STUB_CHOWN_COUNT'] = str(bindir / 'count')
    proc = run_lib_function(env, 'finalize_result', str(result),
                            'P11SCOPE_DEMO_OK', str(work), '0', '0')
    assert proc.returncode != 0
    assert not result.exists()


def test_demo_inner_finalizes_through_lib():
    """Both demo-inner RESULT paths use finalize_result; no direct
    marker write can precede the ownership fixup again."""
    text = (EXAMPLE / 'demo-inner.sh').read_text()
    assert text.count('finalize_result "$WORK/RESULT"') == 2
    assert '>"$WORK/RESULT"' not in text


def parse_docker_calls(log):
    calls, current = [], []
    for line in log.read_text().splitlines():
        if line == 'DOCKER-CALL':
            if current:
                calls.append(current)
            current = []
        else:
            assert line.startswith('<') and line.endswith('>')
            current.append(line[1:-1])
    if current:
        calls.append(current)
    return calls


def test_docker_build_keeps_spaced_paths_whole(tmp_path):
    """With spaces in the output dir, the build argv still carries each
    path as one word (POSIX positional parameters, no word splitting)."""
    stub = tmp_path / 'p11scope'
    write_p11scope_stub(stub, GOOD_VERSION,
                        (TIER_LINE, 1), (TIER_LINE, 1))
    env = make_phase1_stubs(tmp_path, stub)
    bindir = Path(env['PATH'].split(os.pathsep)[0])
    argv_log = tmp_path / 'docker-argv.log'
    write_executable(
        bindir / 'docker',
        '#!/bin/sh\n'
        '{\n'
        "  printf 'DOCKER-CALL\\n'\n"
        "  printf '<%s>\\n' \"$@\"\n"
        f'}} >>"{argv_log}"\n'
        'prev=\n'
        'for a in "$@"; do\n'
        '  if [ "$prev" = "--iidfile" ]; then '
        'printf "%s" "sha256:stub" >"$a"; fi\n'
        '  prev=$a\n'
        'done\n'
        'if [ "$1" = "image" ]; then printf "sha256:stub 1 []\\n"; fi\n'
        'exit 0\n')
    out = tmp_path / 'out dir with spaces'
    proc = subprocess.run([str(RUN), '--privileged', '--output-dir', str(out)],
                          capture_output=True, text=True, timeout=120,
                          env=env)
    # The stubbed container run writes no RESULT, so the driver must fail
    # honestly *after* a well-formed build, never at build-argument time.
    assert proc.returncode == 1
    assert 'demo failed' in proc.stderr
    calls = parse_docker_calls(argv_log)
    assert calls[0][0] == 'build'
    build = calls[0]
    iidflag = build.index('--iidfile')
    assert build[iidflag + 1] == f'{out}/demo-image.id'
    fflag = build.index('-f')
    assert build[fflag + 1] == f'{EXAMPLE}/Dockerfile.demo'
    assert build[-1] == str(EXAMPLE)
    assert stat.S_IMODE(out.stat().st_mode) == 0o700
