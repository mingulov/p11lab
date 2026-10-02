"""Opt-in exact installed native acceptance in clean Debian 13 containers.

Consumer image contains only declared runtimes. CLI image separately installs
P11Lab and checker wheels. Inputs are archives/app executables, never checkouts.
"""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

from p11lab.catalog import package_data

BUNDLES = json.loads(os.environ.get("P11LAB_TEST_NATIVE_BUNDLES", "{}"))
CONSUMER = os.environ.get("P11LAB_TEST_NATIVE_CONSUMER", "")
CLI = os.environ.get("P11LAB_TEST_NATIVE_CLI", "")
pytestmark = pytest.mark.skipif(
    not BUNDLES or not CONSUMER or not CLI,
    reason="explicit native archives and clean Debian consumer/installed CLI images required",
)

CLI_SCRIPT = r"""
import json,os,subprocess,sys,shutil,signal,time
from pathlib import Path
from p11lab.bundle import read_installation
from p11lab.checker import execute_checker,installed_identity,load_profile
channel=sys.argv[1];root=Path('/evidence');prefix=root/'prefix with spaces';second=root/'second prefix with spaces'
archive=Path('/tmp')/(channel+'.tar.gz');shutil.copyfile('/input/bundle.tar.gz',archive)
sha=__import__('hashlib').sha256(archive.read_bytes()).hexdigest()
def command(args,status=0):
 p=subprocess.run(['p11lab',*args],capture_output=True,text=True,timeout=120)
 assert p.returncode==status,(args,p.stdout,p.stderr)
 return p
args=['install','softhsm2','--channel',channel,'--platform','linux/amd64','--artifact',str(archive),'--sha256',sha]
for path in [prefix,second]:
 result=command([*args,'--prefix',str(path)]);(root/(path.name+'.install.json')).write_text(result.stdout)
installed=read_installation(prefix,environment='softhsm2',channel=channel,platform='linux/amd64')
second_installed=read_installation(second,environment='softhsm2',channel=channel,platform='linux/amd64')
(root/'second-receipt-copy.json').write_bytes(second_installed.receipt_path.read_bytes())
archive.unlink()
state=root/'cli state';state.mkdir(mode=0o700);control=root/'cli control'
pin=root/'pin';so=root/'so';pin.write_bytes(b'1234');so.write_bytes(b'12345678');pin.chmod(0o600);so.chmod(0o600)
# Explicit archive execution has its own verified temporary placement; the
# installation recorded by this attempt is cleaned after the application exits.
result=command(['run','softhsm2','--channel',channel,'--mode','native','--where','host',
 '--artifact','/input/bundle.tar.gz','--sha256',sha,'--cwd','/consumer cwd with spaces',
 '--input','P11LAB_PIN_FILE='+str(pin),'--input','P11LAB_SO_PIN_FILE='+str(so),
 '--output-dir',str(root/'archive run'),'--','true'])
archive_receipt=json.loads((root/'archive run/receipt.json').read_text())
assert archive_receipt['artifacts']['provider']['sha256']==sha
assert not Path(archive_receipt['installation']['prefix']).exists()

def run(extra,argv,status=0,prefix=prefix):
 return command(['run','softhsm2','--channel',channel,'--mode','native','--where','host',
  '--installed-prefix',str(prefix),'--cwd','/consumer cwd with spaces','--state-dir',str(state),
  '--control-dir',str(control),'--input','P11LAB_PIN_FILE='+str(pin),'--input','P11LAB_SO_PIN_FILE='+str(so),
  *extra,'--',*argv],status)
run(['--output-dir',str(root/'cli literal')],['sh','-c','printf "%s\n" "$PWD" "$1"; exit 7','app','literal $(touch forbidden); spaces'],7)
assert (root/'cli literal/application.stdout.log').read_text().splitlines()==['/consumer cwd with spaces','literal $(touch forbidden); spaces']
assert not Path('/consumer cwd with spaces/forbidden').exists()
receipt=json.loads((root/'cli literal/receipt.json').read_text());assert receipt['artifacts']['provider']==installed.artifact.__dict__
run(['--output-dir',str(root/'cli second')],['true'],prefix=second)
# Installed-file damage must fail before touching the selected app/output/state.
module=second/'payload/lib/libsofthsm2.so';original=module.read_bytes();module.write_bytes(b'changed')
run(['--output-dir',str(root/'must not exist')],['touch',str(root/'forbidden')],2,prefix=second)
assert not (root/'must not exist').exists() and not (root/'forbidden').exists();module.write_bytes(original)
run(['--output-dir',str(root/'cli timeout'),'--timeout','2'],['sleep','20'],124)
# Real installed CLI signal handling is a bounded host-process operation.
signalout=root/'cli signal'
args=['p11lab','run','softhsm2','--channel',channel,'--mode','native','--where','host','--installed-prefix',str(prefix),
 '--state-dir',str(state),'--control-dir',str(control),'--output-dir',str(signalout),'--cwd','/consumer cwd with spaces',
 '--','sh','-c','touch "$P11LAB_OUTPUT_DIR/app-ready"; sleep 30']
p=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
try:
 deadline=time.monotonic()+15
 while not (signalout/'app-ready').exists():
  assert p.poll() is None and time.monotonic()<deadline
  time.sleep(.05)
 p.send_signal(signal.SIGTERM);stdout,stderr=p.communicate(timeout=15)
 assert p.returncode==143,(stdout,stderr)
 assert json.loads((signalout/'receipt.json').read_text())['interrupted_signal']==signal.SIGTERM
finally:
 if p.poll() is None:p.kill();p.communicate(timeout=5)

# Native checker is installed separately and uses frozen Task5 selection/completion.
os.environ['SOFTHSM2_CONF']=str(control/'softhsm2.conf')
from pkcs11_check.core.loader import load_module
p11=load_module(prefix/'payload/lib/libsofthsm2.so',interface='auto')
slots=p11.get_slots(token_present=True);selected=[(i,s.slot_id) for i,s in enumerate(slots) if s.get_token().label=='P11Lab'];assert len(selected)==1
from pkcs11_check.raw.rv import expect_rv
from pkcs11_check.raw.types_std import CKR_OK
expect_rv(p11.raw.C_Finalize(None),CKR_OK)
identity=installed_identity();record=execute_checker(installed_root=Path(identity['installed_root']),module=prefix/'payload/lib/libsofthsm2.so',
 slot=selected[0][0],nodes=load_profile('smoke-v1')['nodes'],output_dir=root/'checker',pin='1234',so_pin='12345678',identity=identity)
assert record['returncode']==0 and record['evidence']['complete'] and record['evidence']['observations_complete'],record
(root/'checker-token.json').write_text(json.dumps({'native_slot_id':selected[0][1],'token_present_index':selected[0][0],'installation':str(installed.receipt_path)},indent=2))
(root/'cli-proof.json').write_text(json.dumps({'archive_deleted':not archive.exists(),'checker_separate':True,'prefix':str(prefix),
 'manifest_sha256':installed.manifest_sha256,'receipt_sha256':installed.receipt_sha256,'python':sys.executable,'identity':identity},indent=2))
"""

MANUAL_SCRIPT = r"""
set -eu
for tool in cc gcc readelf docker python3 pkcs11-check; do
 if command -v "$tool" >/dev/null 2>&1; then echo "unexpected consumer tool: $tool" >&2; exit 1; fi
done
prefix='/evidence/prefix with spaces'
second='/evidence/second prefix with spaces'
state='/evidence/manual state'
control='/evidence/manual control'
export P11LAB_PIN_FILE=/evidence/pin P11LAB_SO_PIN_FILE=/evidence/so
adapter="$prefix/payload/bin/p11lab-provider"
"$adapter" --prefix "$prefix" --state "$state" --control "$control" init
"$adapter" --prefix "$prefix" --state "$state" --control "$control" health > /evidence/manual-slots.txt
cp "$state/softhsm2/complete" /evidence/compatible-marker
if P11LAB_LABEL=Incompatible "$adapter" --prefix "$prefix" --state "$state" --control "$control" init; then exit 1; fi
cmp /evidence/compatible-marker "$state/softhsm2/complete"

export SOFTHSM2_CONF="$control/softhsm2.conf"
module="$prefix/payload/lib/libsofthsm2.so"
# Independent generated-key process, with the declared system OpenSSL preloaded.
LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libcrypto.so.3 /input/p11lab-smoke --module "$module" --token-label P11Lab --pin-file /evidence/pin --output /evidence/generated --key-mode generated
/input/provision "$module" /evidence/pin > /evidence/coexistence.txt
for index in 0 1; do
 /input/p11lab-smoke --module "$module" --token-label P11Lab --pin-file /evidence/pin --output "/evidence/persisted-$index" --key-mode existing --key-id 42
done
cmp /evidence/persisted-0/public-key.der /evidence/persisted-1/public-key.der
# Verified reinstall loads from its own new module path against compatible state.
"$second/payload/bin/p11lab-provider" --prefix "$second" --state "$state" --control "$control" exec -- /input/p11lab-smoke --module "$second/payload/lib/libsofthsm2.so" --token-label P11Lab --pin-file /evidence/pin --output /evidence/reinstalled --key-mode existing --key-id 42
cmp /evidence/persisted-0/public-key.der /evidence/reinstalled/public-key.der
# Independent state has a different token and does not expose persistent key 42.
"$adapter" --prefix "$prefix" --state '/evidence/separate state' --control '/evidence/separate control' init
export SOFTHSM2_CONF='/evidence/separate control/softhsm2.conf'
if /input/p11lab-smoke --module "$module" --token-label P11Lab --pin-file /evidence/pin --output /evidence/separate-existing --key-mode existing --key-id 42; then exit 1; fi
/input/p11lab-smoke --module "$module" --token-label P11Lab --pin-file /evidence/pin --output /evidence/separate-generated --key-mode generated
# Preserve corrupted state; enumeration/initialization must not resurrect it.
cp '/evidence/separate state/softhsm2/complete' /evidence/marker-before
find '/evidence/separate state/softhsm2/tokens' -type f -delete
if "$adapter" --prefix "$prefix" --state '/evidence/separate state' --control '/evidence/separate control' init; then exit 1; fi
cmp /evidence/marker-before '/evidence/separate state/softhsm2/complete'
printf '%s\n' 'manual consumer: no compiler/binutils/Python/checker/Docker; persistence, independent state, corruption refusal and reinstall passed' > /evidence/manual-proof.txt
# Remove only an owned disposable second prefix; external tokens remain usable.
rm -rf -- "$second"
export SOFTHSM2_CONF="$control/softhsm2.conf"
/input/p11lab-smoke --module "$module" --token-label P11Lab --pin-file /evidence/pin --output /evidence/after-prefix-removal --key-mode existing --key-id 42
"""


@pytest.mark.parametrize("channel,archive", list(BUNDLES.items()))
def test_exact_installed_debian_native(channel, archive, tmp_path):
    evidence = os.environ.get("P11LAB_TEST_NATIVE_EVIDENCE")
    root = Path(evidence).resolve() / channel if evidence else tmp_path
    root.mkdir(parents=True, exist_ok=False)
    inputs = root / "inputs"
    inputs.mkdir()
    output = root / "results"
    output.mkdir()
    shutil.copyfile(archive, inputs / "bundle.tar.gz")
    for name, variable in [
        ("p11lab-smoke", "P11LAB_TEST_NATIVE_SMOKE"),
        ("provision", "P11LAB_TEST_NATIVE_PROVISION"),
    ]:
        shutil.copyfile(os.environ[variable], inputs / name)
        (inputs / name).chmod(0o755)
    (inputs / "cli.py").write_text(CLI_SCRIPT)
    (inputs / "manual.sh").write_text(MANUAL_SCRIPT)
    (inputs / "verify.py").write_bytes(package_data("consumer/verify.py").read_bytes())
    commands = []

    def execute(image, argv, name, user=True, check=True):
        command = [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev",
            "--mount",
            f"type=bind,src={inputs},dst=/input,readonly",
            "--mount",
            f"type=bind,src={output},dst=/evidence",
        ]
        if user:
            command += ["--user", f"{os.getuid()}:{os.getgid()}"]
        else:
            command.remove("--read-only")
            # Root in this disposable fault container must traverse the caller's
            # 0700 installed prefix; all ordinary consumer runs retain cap-drop ALL.
            command += ["--cap-add", "DAC_OVERRIDE"]
        command += [image, *argv]
        commands.append(command)
        result = subprocess.run(command, capture_output=True, text=True, timeout=1100)
        (root / (name + ".stdout.log")).write_text(result.stdout)
        (root / (name + ".stderr.log")).write_text(result.stderr)
        (root / "commands.json").write_text(json.dumps(commands, indent=2))
        if check:
            assert result.returncode == 0, (name, result.stdout, result.stderr)
        return result

    execute(CLI, ["python", "/input/cli.py", channel], "installed-cli-checker")
    execute(CONSUMER, ["sh", "/input/manual.sh"], "manual-consumer")
    for name in [
        "generated",
        "persisted-0",
        "persisted-1",
        "reinstalled",
        "separate-generated",
        "after-prefix-removal",
    ]:
        result = execute(
            CLI, ["python", "/input/verify.py", "/evidence/" + name], "oracle-" + name
        )
        assert "altered message rejected" in result.stdout
    # Own fresh container: deliberately hide libcrypto, proving loader dependency
    # failure before state initialization/application even on supported Debian.
    result = execute(
        CONSUMER,
        [
            "sh",
            "-c",
            r"""
set -eu
mv /usr/lib/x86_64-linux-gnu/libcrypto.so.3 /usr/lib/x86_64-linux-gnu/libcrypto.so.3.hidden
if '/evidence/prefix with spaces/payload/bin/p11lab-provider' --prefix '/evidence/prefix with spaces' --state /evidence/missing-state --control /evidence/missing-control exec -- touch /evidence/missing-executed; then exit 1; fi
[ ! -e /evidence/missing-state ] && [ ! -e /evidence/missing-control ] && [ ! -e /evidence/missing-executed ]
""",
        ],
        "missing-dependency",
        user=False,
    )
    assert "missing or incompatible" in result.stderr
    (root / "acceptance.json").write_text(
        json.dumps(
            {
                "channel": channel,
                "archive_sha256": hashlib.sha256(
                    Path(archive).read_bytes()
                ).hexdigest(),
                "platform": "debian13-amd64",
                "scope": "native loading within Docker-supplied Debian; no daemon in consumer",
                "consumer_image": CONSUMER,
                "installed_cli_checker_image": CLI,
                "complete": True,
            },
            indent=2,
        )
    )
