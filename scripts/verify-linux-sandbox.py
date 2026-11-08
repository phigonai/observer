"""Run real kernel denial checks on a built Guardian runner, in isolated files."""
import ctypes
import hashlib
import json
import os
import pathlib
import signal
import socket
import subprocess
import struct
import sys
import tempfile
import time

runner = str(pathlib.Path(sys.argv[1]).resolve(strict=True))
executable = str(pathlib.Path(sys.executable).resolve(strict=True))
digest = hashlib.sha256(pathlib.Path(executable).read_bytes()).hexdigest()
elf = pathlib.Path(executable).read_bytes()
headers = struct.unpack_from("<Q", elf, 32)[0]
header_size, header_count = struct.unpack_from("<HH", elf, 54)
execute_paths = [executable]
for index in range(header_count):
    offset = headers + index * header_size
    if struct.unpack_from("<I", elf, offset)[0] == 3:
        start = struct.unpack_from("<Q", elf, offset + 8)[0]
        interpreter = elf[start:].split(b"\0", 1)[0].decode()
        execute_paths.append(str(pathlib.Path(interpreter).resolve(strict=True)))
program = r'''
import fcntl,os,pathlib,socket,subprocess,sys
allowed=pathlib.Path(sys.argv[1]); secret=pathlib.Path(sys.argv[2])
(allowed/'permitted.txt').write_text('works')
assert (allowed/'permitted.txt').read_text()=='works'
def denied(name,operation):
    try: operation()
    except PermissionError: print('PASS '+name,flush=True)
    else: raise AssertionError(name+' was not blocked')
denied('protected file read',lambda:secret.read_text())
denied('protected file write',lambda:secret.write_text('changed'))
denied('protected file deletion',lambda:secret.unlink())
denied('protected file permission change',lambda:os.chmod(secret,0o777))
denied('protected file owner change',lambda:os.chown(secret,os.getuid(),os.getgid()))
denied('protected file timestamp change',lambda:os.utime(secret,(1,1)))
denied('protected file extended attributes',lambda:os.setxattr(secret,'user.phigon_test',b'changed'))
os.symlink(secret,allowed/'alias')
denied('symlink escape',lambda:(allowed/'alias').read_text())
denied('unapproved child application',lambda:subprocess.run(['/usr/bin/dash','-c','exit 0'],check=True))
denied('TCP socket',lambda:socket.socket(socket.AF_INET,socket.SOCK_STREAM))
denied('UDP socket',lambda:socket.socket(socket.AF_INET,socket.SOCK_DGRAM))
# These calls target a pipe, never the user's real terminal. EPERM (rather than
# the ordinary ENOTTY) proves the filter rejects the dangerous ioctl requests.
denied('terminal keystroke injection ioctl',lambda:fcntl.ioctl(1,0x5412,b'x'))
denied('legacy console ioctl',lambda:fcntl.ioctl(1,0x541c,b'\0'))
fcntl.ioctl(1,0x541b,b'\0'*4) # Ordinary pipe FIONREAD remains usable.
child=subprocess.run([sys.executable,'-c',"import pathlib,sys;pathlib.Path(sys.argv[1]).write_text('escaped')",str(secret)],capture_output=True)
assert child.returncode!=0 and b'PermissionError' in child.stderr
print('PASS sandbox inherited by approved child application',flush=True)
'''
with tempfile.TemporaryDirectory(prefix="phigon-sandbox-") as directory:
    base = pathlib.Path(directory)
    allowed = base / "allowed"
    allowed.mkdir()
    secret = base / "protected.txt"
    secret.write_text("untouched")
    profile = {"name": "Kernel regression test", "platform": "linux", "read_paths": ["/usr", "/etc", str(allowed)],
               "write_paths": [str(allowed)], "execute_paths": execute_paths, "network": "deny", "require_cgroup": False}
    result = subprocess.run([runner, "--sha256", digest, "--cwd", str(allowed), "--sandbox", json.dumps([profile]),
                             "--", executable, "-c", program, str(allowed), str(secret)], capture_output=True, text=True, timeout=20)
    abi = ctypes.CDLL(None, use_errno=True).syscall(444, 0, 0, 1)
    if abi < 3:
        assert result.returncode == 77, result
        print("PASS unsupported kernel fails closed; live Landlock tests require ABI 3+")
        if "--require-landlock" in sys.argv:
            raise SystemExit(1)
    else:
        print(result.stdout, end="")
        assert result.returncode == 0, (result.returncode, result.stderr)
        assert secret.read_text() == "untouched"
        print("PASS real Linux filesystem, execution and network sandbox")
        with secret.open("rb") as inherited:
            leaked = subprocess.run([runner, "--sha256", digest, "--cwd", str(allowed), "--sandbox", json.dumps([profile]),
                                     "--", executable, "-c", "import sys;print(sys.stdin.read())"],
                                    stdin=inherited, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        assert leaked.returncode == 77 and b"untouched" not in leaked.stdout, "inherited stdin bypassed file restrictions"
        with secret.open("r+b") as inherited:
            modified = subprocess.run([runner, "--sha256", digest, "--cwd", str(allowed), "--sandbox", json.dumps([profile]),
                                       "--", executable, "-c", "import os;os.write(1,b'changed')"],
                                      stdout=inherited, stderr=subprocess.PIPE, timeout=10)
        assert modified.returncode == 77 and secret.read_text() == "untouched", "inherited stdout bypassed file restrictions"
        with secret.open("r+b") as inherited:
            modified = subprocess.run([runner, "--sha256", digest, "--cwd", str(allowed), "--sandbox", json.dumps([profile]),
                                       "--", executable, "-c", "import os;os.write(2,b'changed')"],
                                      stdout=subprocess.PIPE, stderr=inherited, timeout=10)
        assert modified.returncode == 77 and secret.read_text() == "untouched", "inherited stderr or diagnostic output changed a protected file"
        with open("/dev/zero", "rb") as inherited:
            device = subprocess.run([runner, "--sha256", digest, "--cwd", str(allowed), "--sandbox", json.dumps([profile]),
                                     "--", executable, "-c", "print('unexpected device access')"],
                                    stdin=inherited, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        assert device.returncode == 77 and not device.stdout, "arbitrary device stream was inherited"
        master, terminal = os.openpty()
        try:
            interactive = subprocess.run([runner, "--sha256", digest, "--cwd", str(allowed), "--sandbox", json.dumps([profile]),
                                          "--", executable, "-c", "import os;assert os.isatty(0);print('terminal accepted')"],
                                         stdin=terminal, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
            assert interactive.returncode == 0 and b"terminal accepted" in interactive.stdout, interactive.stderr
        finally:
            os.close(master); os.close(terminal)
        print("PASS inherited file descriptors cannot bypass read/write restrictions")
        print("PASS arbitrary devices rejected and interactive terminals remain usable")
        args = [runner, "--sha256", digest, "--cwd", str(allowed), "--sandbox", json.dumps([profile]),
                "--", executable, "-c", "print('unexpected socket access')"]
        for kind in ("tcp", "unix", "abstract"):
            family = socket.AF_INET if kind == "tcp" else socket.AF_UNIX
            with socket.socket(family, socket.SOCK_STREAM) as listener:
                address = ("127.0.0.1", 0) if kind == "tcp" else ("\0" + str(base) if kind == "abstract" else str(base / "outside-service.sock"))
                listener.bind(address); listener.listen(1)
                with socket.socket(family, socket.SOCK_STREAM) as client:
                    client.connect(listener.getsockname())
                    connection, _ = listener.accept()
                    with connection:
                        rejected = subprocess.run(args, stdin=client, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
                        assert rejected.returncode == 77 and not rejected.stdout, "inherited service socket bypassed network restriction"
        print("PASS inherited TCP and named Unix service sockets remain blocked")
        # Network "inherit" keeps IP networking but must not reach host services
        # (the session bus, systemd, Docker, ssh-agent) through Unix sockets.
        inherit = dict(profile, network="inherit")
        services = []
        for address in (str(base / "host-service.sock"), "\0" + str(base) + "-host-service"):
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(address); listener.listen(4)
            services.append(listener)
        inherit_program = r'''
import os,socket,subprocess,sys
def denied(name,operation):
    try: operation()
    except PermissionError: print('PASS '+name,flush=True)
    else: raise AssertionError(name+' was not blocked')
for address in sys.argv[1:3]:
    address='\0'+address[1:] if address.startswith('@') else address
    denied('host Unix service '+('abstract' if address.startswith('\0') else 'path'),lambda:socket.socket(socket.AF_UNIX).connect(address))
denied('Unix datagram socketpair',lambda:socket.socketpair(socket.AF_UNIX,socket.SOCK_DGRAM))
leaked='/proc/self/fd/'+sys.argv[3]
assert not os.path.exists(leaked) or not os.readlink(leaked).startswith('socket:'),'an inherited descriptor reached the workload'
print('PASS inherited descriptors beyond stdio are closed',flush=True)
socket.socket(socket.AF_INET,socket.SOCK_STREAM).close()
left,right=socket.socketpair(); left.sendall(b'x'); assert right.recv(1)==b'x'
child=subprocess.run([sys.executable,'-c','print(42)'],capture_output=True,text=True)
assert child.stdout.strip()=='42',child
print('PASS IP sockets, stream socketpairs and child pipes still work',flush=True)
'''
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as leaked:
            leaked.connect(str(base / "host-service.sock"))
            os.set_inheritable(leaked.fileno(), True)
            unix_result = subprocess.run([runner, "--sha256", digest, "--cwd", str(allowed), "--sandbox", json.dumps([inherit]),
                                          "--", executable, "-c", inherit_program, str(base / "host-service.sock"),
                                          "@" + str(base) + "-host-service", str(leaked.fileno())],
                                         capture_output=True, text=True, timeout=20, pass_fds=(leaked.fileno(),))
        print(unix_result.stdout, end="")
        assert unix_result.returncode == 0, (unix_result.returncode, unix_result.stderr)
        for kind, address in (("path", str(base / "host-service.sock")), ("abstract", "\0" + str(base) + "-host-service")):
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.connect(address)
                rejected = subprocess.run([runner, "--sha256", digest, "--cwd", str(allowed), "--sandbox", json.dumps([inherit]),
                                           "--", executable, "-c", "print('unexpected service stream')"],
                                          stdin=client, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
                assert rejected.returncode == 77 and not rejected.stdout, f"inherited {kind} service socket bypassed inherit mode"
        for listener in services:
            listener.close()
        print("PASS network inherit blocks host Unix services, including as standard streams")
        # Without Landlock's signal scope a same-user workload can still kill the
        # supervisor through one of its other thread IDs. It must die with it.
        attacker = r'''
import os,pathlib,signal,sys,time
pathlib.Path(sys.argv[1]).write_text(str(os.getpid()))
supervisor=os.getppid()
threads=[int(t) for t in os.listdir(f'/proc/{supervisor}/task') if int(t)!=supervisor]
try:
    os.kill(threads[0],signal.SIGKILL); print('KILLED',flush=True)
except PermissionError:
    print('BLOCKED',flush=True)
time.sleep(30)
'''
        marker = allowed / "workload.pid"
        watched = dict(inherit, read_paths=inherit["read_paths"] + ["/proc"])
        supervisor = subprocess.Popen([runner, "--sha256", digest, "--cwd", str(allowed), "--sandbox", json.dumps([watched]),
                                       "--", executable, "-c", attacker, str(marker)],
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        def running(pid):
            try:
                return pathlib.Path(f"/proc/{pid}/stat").read_text().split(") ", 1)[1][0] != "Z"
            except FileNotFoundError:
                return False
        workload = None
        try:
            outcome = supervisor.stdout.readline().strip()
            workload = int(marker.read_text())
            if outcome == "KILLED":
                supervisor.wait(timeout=10)
                for _ in range(100):
                    if not running(workload):
                        break
                    time.sleep(.02)
                assert not running(workload), "the workload outlived its killed supervisor"
                print("PASS a workload that kills its supervisor through a thread ID dies with it")
            else:
                assert outcome == "BLOCKED" and supervisor.poll() is None, (outcome, supervisor.poll())
                print("PASS Landlock's signal scope keeps the workload from signalling the supervisor")
        finally:
            if supervisor.poll() is None:
                supervisor.terminate()
                supervisor.wait(timeout=10)
            if workload and running(workload):
                os.kill(workload, signal.SIGKILL)
        # Exercise the actual Node observer integration: libuv's subprocess
        # streams are Unix socketpairs, unlike Python's anonymous OS pipes.
        modules = pathlib.Path(__file__).resolve().parent.parent / "dist" / "src"
        code = "\n".join([
            "import {executeManagedCommand} from " + json.dumps((modules / "guardian-managed-exec.js").as_uri()) + ";",
            "import {createExecutionManifest,executionEnvironment} from " + json.dumps((modules / "guardian-execution-manifest.js").as_uri()) + ";",
            "const environment=executionEnvironment(process.env);",
            "const options=" + json.dumps({"executable": executable, "cwd": str(allowed), "agentId": "test", "arguments": ["-c", "print('managed-node-relay')"], "sandbox": json.dumps([profile])}) + ";",
            "const manifest=await createExecutionManifest({...options,environment});",
            "const result=await executeManagedCommand({executable:manifest.executable,arguments:manifest.arguments,agentId:'test',sessionId:'sandbox-test',manifest,environment,dataDirectory:" + json.dumps(str(base / "observer-data")) + "});",
            "if(result.exitCode!==0)throw Error('Node managed launch failed with code '+result.exitCode);",
        ])
        integrated = subprocess.run(["node", "--input-type=module", "-e", code], capture_output=True, text=True, timeout=20)
        assert integrated.returncode == 0 and "managed-node-relay" in integrated.stdout, (integrated.returncode, integrated.stderr)
        print("PASS actual Node managed launch supports offline sandbox output")
