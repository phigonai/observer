"""Verify OS quotas and identity isolation inside uniquely created test cgroups.

Requires root in an isolated Linux CI host with cpu/memory/pids delegation.
Only the new subtree is configured. No ancestor controller is changed.
"""
import hashlib
import json
import os
import pathlib
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import uuid

assert os.geteuid() == 0, "This identity-isolation test requires a root test supervisor"
source_runner = pathlib.Path(sys.argv[1]).resolve(strict=True)
executable = pathlib.Path(sys.executable).resolve(strict=True)
elf = executable.read_bytes()
digest = hashlib.sha256(elf).hexdigest()
headers = struct.unpack_from("<Q", elf, 32)[0]
size, count = struct.unpack_from("<HH", elf, 54)
execute_paths = [str(executable)]
for index in range(count):
    offset = headers + index * size
    if struct.unpack_from("<I", elf, offset)[0] == 3:
        start = struct.unpack_from("<Q", elf, offset + 8)[0]
        execute_paths.append(str(pathlib.Path(elf[start:].split(b"\0", 1)[0].decode()).resolve(strict=True)))

root = pathlib.Path(os.environ.get("PHIGON_TEST_CGROUP_ROOT", "/sys/fs/cgroup")) / ("phigon-resource-test-" + uuid.uuid4().hex)
root.mkdir(mode=0o700)
try:
    (root / "cgroup.subtree_control").write_text("+cpu +memory +pids")
    with tempfile.TemporaryDirectory(prefix="phigon-resources-") as directory:
        base = pathlib.Path(directory)
        base.chmod(0o755)
        runner = base / "guardian-runner"
        shutil.copyfile(source_runner, runner)
        runner.chmod(0o755)
        allowed = base / "workload"
        allowed.mkdir(mode=0o700)
        os.chown(allowed, 65534, 65534)
        secret = base / "supervisor-only"
        secret.write_text("protected")
        secret.chmod(0o600)
        profile = {"name": "Quotas and isolated identity", "platform": "linux", "network": "deny",
                   "read_paths": ["/usr", "/etc", str(allowed)], "write_paths": [str(allowed)],
                   "execute_paths": execute_paths, "require_cgroup": True, "run_as": {"uid": 65534, "gid": 65534},
                   "limits": {"max_processes": 12, "max_memory_bytes": 256 << 20, "max_cpu_percent": 20, "max_runtime_seconds": 3}}
        def run(code, current=profile, cgroup=root, inspect=False):
            args = [str(runner), "--sha256", digest, "--cwd", str(allowed), "--sandbox", json.dumps([current]),
                    "--cgroup-root", str(cgroup), "--", str(executable), "-c", code]
            process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                if inspect:
                    for _ in range(100):
                        boundaries = list(root.glob("guardian-*"))
                        if boundaries and (boundaries[0] / "cpu.max").read_text().split()[0] != "max": break
                        if process.poll() is not None: raise AssertionError(process.communicate())
                        time.sleep(.01)
                    assert len(boundaries) == 1
                    boundary = boundaries[0]
                    assert (boundary / "pids.max").read_text().strip() == "12"
                    assert (boundary / "memory.max").read_text().strip() == str(256 << 20)
                    assert (boundary / "memory.swap.max").read_text().strip() == "0"
                    quota, period = map(int, (boundary / "cpu.max").read_text().split())
                    assert period == 100000 and 0 < quota <= os.cpu_count() * 20000
                    print("PASS kernel memory, CPU, swap and process limits installed before workload")
                output, error = process.communicate(timeout=20)
                return subprocess.CompletedProcess(args, process.returncode, output, error)
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.communicate(timeout=10)

        program = r'''
import ctypes,errno,os,pathlib,subprocess,sys,time
assert os.getuid()==65534 and os.geteuid()==65534 and os.getgid()==65534 and not os.getgroups()
header=(ctypes.c_uint32*2)(0x20080522,0)
caps=(ctypes.c_uint32*6)()
assert ctypes.CDLL(None).capget(ctypes.byref(header),ctypes.byref(caps))==0
assert not any(caps),'workload retained Linux capabilities'
print('PASS workload capabilities and supplementary groups are cleared',flush=True)
try: os.kill(os.getppid(),0)
except PermissionError: print('PASS workload cannot signal root supervisor',flush=True)
else: raise AssertionError('supervisor signal permission leaked')
pathlib.Path('identity.txt').write_text(str(os.getuid()))
children=[]
try:
    for index in range(24):
        children.append(subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)']))
except OSError as error:
    assert error.errno==errno.EAGAIN,error
    print('PASS kernel blocks child creation at process limit',flush=True)
else: raise AssertionError('process limit was bypassed')
pathlib.Path('children.json').write_text(__import__('json').dumps([c.pid for c in children]))
time.sleep(30)
'''
        result = run(program, inspect=True)
        print(result.stdout, end="")
        assert result.returncode == 77 and "runtime limit" in result.stderr, (result.returncode, result.stderr)
        assert (allowed / "identity.txt").read_text() == "65534"
        for pid in json.loads((allowed / "children.json").read_text()):
            stat = pathlib.Path(f"/proc/{pid}/stat")
            assert not stat.exists() or stat.read_text().split(") ", 1)[1][0] == "Z", "runtime limit left a descendant alive"
        assert list(root.iterdir()) and not list(root.glob("guardian-*")), "boundary leaked"
        print("PASS runtime limit kills cgroup descendants and removes the boundary")
        memory = dict(profile, limits={"max_memory_bytes": 64 << 20, "max_runtime_seconds": 5})
        result = run("data=bytearray(256<<20);print('unexpected allocation',flush=True)", memory)
        assert result.returncode == 77 and "unexpected allocation" not in result.stdout, (result.returncode, result.stderr)
        print("PASS memory quota kills bounded over-budget workload")
        # Required quotas and account separation must never degrade to a group.
        result = run("print('unexpected launch')", cgroup="")
        assert result.returncode == 77 and not result.stdout, result
        print("PASS missing required cgroup blocks launch")
        result = subprocess.run([str(runner), "__sandbox", json.dumps([profile]), digest, str(allowed), str(os.getpid()), str(executable), "-c", "print('unexpected launch')"], capture_output=True, text=True, timeout=10)
        assert result.returncode == 77 and not result.stdout, result
        print("PASS sandbox helper refuses a claimed identity that was not established")
finally:
    root.rmdir()
