"""Run real kernel denial checks on a built Guardian runner, in isolated files."""
import ctypes
import hashlib
import json
import os
import pathlib
import socket
import subprocess
import struct
import sys
import tempfile

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
