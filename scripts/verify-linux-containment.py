"""Exercise a built Guardian runner against real Linux process boundaries.

Run as a user with a delegated cgroup subtree, or as root in an isolated CI host.
Only uniquely named test cgroups and processes created here are modified.
"""
import hashlib
import os
import pathlib
import signal
import subprocess
import sys
import tempfile
import time
import uuid


runner = str(pathlib.Path(sys.argv[1]).resolve(strict=True))
shell = "/usr/bin/dash"
digest = hashlib.sha256(pathlib.Path(shell).read_bytes()).hexdigest()


def alive(pid):
    try:
        return pathlib.Path(f"/proc/{pid}/stat").read_text().split(") ", 1)[1][0] != "Z"
    except FileNotFoundError:
        return False


def exercise(root, detached):
    with tempfile.TemporaryDirectory(prefix="phigon-guardian-linux-") as directory:
        marker = pathlib.Path(directory) / "child.pid"
        program = ("setsid " if detached else "") + 'sleep 120 & echo $! > "$1"; wait'
        process = subprocess.Popen(
            [runner, "--sha256", digest, "--cwd", directory, "--cgroup-root", root,
             "--", shell, "-c", program, "agent", str(marker)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        child = None
        try:
            for _ in range(100):
                if marker.exists() and marker.read_text().strip():
                    child = int(marker.read_text())
                    break
                if process.poll() is not None:
                    break
                time.sleep(.05)
            if not child or not alive(child):
                output = process.communicate(timeout=5)
                raise AssertionError((process.returncode, output))
            process.send_signal(signal.SIGTERM)
            output = process.communicate(timeout=10)
            assert process.returncode == 77, (process.returncode, output)
            for _ in range(100):
                if not alive(child):
                    break
                time.sleep(.05)
            assert not alive(child), "Managed descendant escaped containment"
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            if child and alive(child):
                os.kill(child, signal.SIGKILL)


exercise("", False)
print("PASS Linux managed process-group termination", flush=True)
bad = subprocess.run(
    [runner, "--sha256", digest, "--cwd", "/tmp", "--cgroup-root", "/tmp",
     "--", shell, "-c", "exit 0"], capture_output=True, timeout=10,
)
assert bad.returncode == 77, (bad.returncode, bad.stderr)
print("PASS configured non-cgroup boundary fails closed", flush=True)
base = pathlib.Path(os.environ.get("PHIGON_TEST_CGROUP_ROOT", "/sys/fs/cgroup"))
root = base / ("phigon-guardian-test-" + uuid.uuid4().hex)
root.mkdir(mode=0o700)
try:
    exercise(str(root), True)
    print("PASS Linux cgroup contains setsid descendant and removes boundary", flush=True)
finally:
    root.rmdir()
