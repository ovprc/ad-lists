"""Exercise the delivered macOS helper with synthetic loopback-only traffic.

Usage: python3 tests/smoke_macos_helper.py <macos-x64-or-arm64-package-dir>
Requires a disposable macOS runner with passwordless sudo. Never creates a TUN.
"""
import contextlib
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time
import uuid


def exact(channel, size):
    result = bytearray()
    while len(result) < size:
        block = channel.recv(size - len(result))
        if not block:
            raise RuntimeError("Helper closed the channel before a complete response")
        result.extend(block)
    return bytes(result)


@contextlib.contextmanager
def helper(executable):
    with tempfile.TemporaryDirectory(prefix="mintun-smoke-") as temporary:
        address = str(Path(temporary).resolve() / "h")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(address)
            listener.listen(1)
            listener.settimeout(90)
            process = subprocess.Popen(
                ["sudo", "-n", str(executable), "--mintun-core-helper", address],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            failed = False
            try:
                channel, _ = listener.accept()
                with channel:
                    channel.settimeout(90)
                    yield channel, process
            except BaseException:
                failed = True
                raise
            finally:
                try:
                    _, stderr = process.communicate(timeout=20)
                except subprocess.TimeoutExpired:
                    subprocess.run(["sudo", "-n", "kill", "-TERM", str(process.pid)],
                                   check=False, capture_output=True, timeout=10)
                    _, stderr = process.communicate(timeout=20)
                if failed and stderr:
                    sys.stderr.buffer.write(stderr[:8192])


def authenticate(port, username, password):
    deadline = time.monotonic() + 15
    while True:
        try:
            channel = socket.create_connection(("127.0.0.1", port), timeout=3)
            break
        except OSError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.1)
    with channel:
        channel.sendall(b"\x05\x01\x02")
        if exact(channel, 2) != b"\x05\x02":
            raise RuntimeError("Core did not require SOCKS username/password authentication")
        user, secret = username.encode(), password.encode()
        channel.sendall(b"\x01" + bytes([len(user)]) + user + bytes([len(secret)]) + secret)
        return exact(channel, 2)


def main():
    if sys.platform != "darwin" or os.geteuid() == 0:
        raise RuntimeError("Run as an ordinary user on a disposable macOS runner")
    package = Path(sys.argv[1]).resolve()
    executable = package / "MinTunClient.app/Contents/MacOS/MinTunClient"
    core = package / "MinTunClient.app/Contents/Resources/core"
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    username, password = "mintun-smoke", uuid.uuid4().hex
    configuration = {
        "log": {"disabled": True},
        "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": port,
                      "users": [{"username": username, "password": password}]}],
        "outbounds": [{"type": "direct"}],
    }
    request = json.dumps({"directory": str(core), "version": "1.15.0-alpha.13",
                          "action": "run", "proxy": None,
                          "json": json.dumps(configuration)}).encode()
    with helper(executable) as (channel, process):
        channel.sendall(struct.pack("!I", len(request)) + request + struct.pack("!I", 0))
        marker = exact(channel, 1)
        if marker == b"\x00":
            size, = struct.unpack("!I", exact(channel, 4))
            if not 1 <= size <= 4096:
                raise RuntimeError("Helper startup diagnostic exceeded bounds")
            raise RuntimeError("Helper rejected the bundled core: " + exact(channel, size).decode())
        if marker != b"\x01":
            raise RuntimeError("Invalid helper startup marker")
        rejected = authenticate(port, username, "incorrect-synthetic-password")
        if rejected[0] != 1 or rejected[1] == 0:
            raise RuntimeError("SOCKS did not correctly reject an incorrect password")
        if authenticate(port, username, password) != b"\x01\x00":
            raise RuntimeError("SOCKS rejected the correct password")
        channel.sendall(b"\x00")
        if exact(channel, 1) != b"\x00" or exact(channel, 4) != b"\x00\x00\x00\x00":
            raise RuntimeError("Shutdown/cache framing was not preserved")
    if process.returncode != 0:
        raise RuntimeError("Owned helper did not stop successfully")

    sensitive_marker = "synthetic-secret-" + uuid.uuid4().hex
    malformed = json.dumps({"unexpected_secret": sensitive_marker}).encode()
    with helper(executable) as (channel, process):
        channel.sendall(struct.pack("!I", len(malformed)) + malformed)
        if exact(channel, 1) != b"\x00":
            raise RuntimeError("Malformed request was not rejected with an error frame")
        size, = struct.unpack("!I", exact(channel, 4))
        if not 1 <= size <= 4096:
            raise RuntimeError("Malformed-request diagnostic exceeded bounds")
        diagnostic = exact(channel, size).decode("utf-8", errors="strict")
        if sensitive_marker in diagnostic:
            raise RuntimeError("Helper leaked request contents in its diagnostic")
    if process.returncode == 0:
        raise RuntimeError("Malformed request unexpectedly succeeded")
    print("PASS macOS delivered helper: authenticated official core, bounded private startup errors, "
          "SOCKS password rejection/acceptance, graceful owned shutdown; no TUN or external traffic")


if __name__ == "__main__":
    main()
