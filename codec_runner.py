#!/usr/bin/env python3
"""Bounded, stdin-only bridge between QML and untrusted command output (Linux)."""

import base64
import ctypes
import json
import os
from pathlib import Path
import resource
import selectors
import signal
import stat
import subprocess
import sys
import time

MAX_DATA = 256 * 1024
MAX_PARAM = 4096
MAX_REQUEST = 384 * 1024
MAX_STDERR = 4096
MAX_KEY_FILE = 64 * 1024
TIMEOUT = 10.0
PASTE_TIMEOUT = 3.0
CHUNK = 8192


class Rejected(Exception):
    """Only fixed, non-sensitive messages from this exception reach QML."""


def harden():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024,) * 2)
    resource.setrlimit(resource.RLIMIT_CPU, (10, 10))


def subreaper():
    # Adopt grandchildren so a killed wrapper cannot leave unreaped producers.
    if ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) != 0:
        raise Rejected("Cannot enable process cleanup")


def remaining(deadline):
    left = deadline - time.monotonic()
    if left <= 0:
        raise Rejected("Operation timed out")
    return min(left, 0.05)


def read_request(deadline):
    """Read to EOF with a byte ceiling, including stalled/streaming callers."""
    data = bytearray()
    os.set_blocking(0, False)
    with selectors.SelectSelector() as sel:
        sel.register(0, selectors.EVENT_READ)
        while True:
            for _, _ in sel.select(remaining(deadline)):
                chunk = os.read(0, min(CHUNK, MAX_REQUEST - len(data) + 1))
                if not chunk:
                    return bytes(data)
                if len(chunk) > MAX_REQUEST - len(data):
                    raise Rejected("Request exceeds 384 KiB")
                data.extend(chunk)


def parse_request(raw):
    try:
        request = json.loads(raw)
        if not isinstance(request, dict) or set(request) != {"id", "data", "params"}:
            raise ValueError()
        algo, encoded, params = request["id"], request["data"], request["params"]
        if not isinstance(algo, str) or not isinstance(encoded, str):
            raise ValueError()
        if len(encoded) > 4 * ((MAX_DATA + 2) // 3):
            raise ValueError()
        data = base64.b64decode(encoded, validate=True)
        if len(data) > MAX_DATA or not isinstance(params, dict) or len(params) > 4:
            raise ValueError()
        for key, value in params.items():
            if (not isinstance(key, str) or len(key) > 32 or not isinstance(value, str)
                    or len(value.encode("utf-8")) > MAX_PARAM):
                raise ValueError()
        return algo, data, params
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise Rejected("Invalid or oversized request") from None


def cleanup(proc):
    # Always address the original group, even after its leader has exited.
    # SIGKILL is deliberate: overflow/cancellation must stop a producer that
    # ignores SIGTERM. These jobs have no persistent state to flush.
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    proc.wait()
    while True:
        try:
            os.waitpid(-1, 0)
        except ChildProcessError:
            break


def supervise(argv, payload, deadline, output_limit=MAX_DATA):
    """Drain both pipes while writing stdin; never use an unbounded collector."""
    subreaper()
    # Block cancellation until the child is owned by the finally block. The
    # child restores its mask and dies if this supervisor disappears abruptly.
    signals = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)
    old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, signals)
    parent_pid = os.getpid()
    libc = ctypes.CDLL(None, use_errno=True)

    def child_setup():
        if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent_pid:
            os._exit(1)
        signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)

    proc = None
    output = bytearray()
    stderr_size = 0
    offset = 0
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, start_new_session=True,
                                preexec_fn=child_setup)
        signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
        with selectors.DefaultSelector() as sel:
            for stream, kind in ((proc.stdout, "out"), (proc.stderr, "err")):
                os.set_blocking(stream.fileno(), False)
                sel.register(stream, selectors.EVENT_READ, kind)
            if payload:
                os.set_blocking(proc.stdin.fileno(), False)
                sel.register(proc.stdin, selectors.EVENT_WRITE, "in")
            else:
                proc.stdin.close()
            while sel.get_map() or proc.poll() is None:
                for key, _ in sel.select(remaining(deadline)):
                    if key.data == "in":
                        try:
                            offset += os.write(key.fd, payload[offset:offset + CHUNK])
                        except BrokenPipeError:
                            offset = len(payload)
                        if offset == len(payload):
                            sel.unregister(key.fileobj)
                            key.fileobj.close()
                        continue
                    size = len(output) if key.data == "out" else stderr_size
                    limit = output_limit if key.data == "out" else MAX_STDERR
                    chunk = os.read(key.fd, min(CHUNK, limit - size + 1))
                    if not chunk:
                        sel.unregister(key.fileobj)
                        key.fileobj.close()
                        continue
                    if len(chunk) > limit - size:
                        raise Rejected("Output exceeds 256 KiB" if key.data == "out"
                                       else "Error output exceeds 4 KiB")
                    if key.data == "out":
                        output.extend(chunk)
                    else:
                        # Child diagnostics may contain private paths/data.
                        stderr_size += len(chunk)
            if proc.returncode != 0:
                raise Rejected("Operation failed (check input, parameters and dependencies)")
            return bytes(output)
    finally:
        # Do not let a second cancellation interrupt cleanup and reaping.
        for sig in signals:
            signal.signal(sig, signal.SIG_IGN)
        signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
        if proc is not None:
            cleanup(proc)
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                stream.close()


def memory_fd(data):
    """Anonymous memory, no shared pathname, inherited only by the exec below."""
    fd = os.memfd_create("codec", os.MFD_CLOEXEC)
    os.fchmod(fd, 0o600)
    with os.fdopen(os.dup(fd), "wb") as writer:
        writer.write(data)
    os.lseek(fd, 0, os.SEEK_SET)
    return fd


def exec_tool(argv, data, extra_fd=None):
    fd = memory_fd(data)
    os.dup2(fd, 0)
    os.close(fd)
    if extra_fd is not None:
        os.set_inheritable(extra_fd, True)
    # No shell, user data, password, key, IV, or key pathname in argv/env.
    os.execv(argv[0], argv)


def raw_aes(algo, data, params):
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    key = bytes.fromhex(params.get("key", ""))
    iv = bytes.fromhex(params.get("iv", ""))
    if len(key) != 32 or len(iv) != 16:
        raise Rejected("AES needs a 32-byte key and a 16-byte IV")
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    if algo == "aes-key-encrypt":
        padder = padding.PKCS7(128).padder()
        padded = padder.update(data) + padder.finalize()
        encryptor = cipher.encryptor()
        result = encryptor.update(padded) + encryptor.finalize()
    else:
        decryptor = cipher.decryptor()
        padded = decryptor.update(data) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        result = unpadder.update(padded) + unpadder.finalize()
    if len(result) > MAX_DATA:
        raise Rejected("Output exceeds 256 KiB")
    sys.stdout.buffer.write(result)


def worker(raw):
    algo, data, params = parse_request(raw)
    if algo in ("aes-key-encrypt", "aes-key-decrypt"):
        raw_aes(algo, data, params)
    elif algo in ("aes-encrypt", "aes-decrypt"):
        password = params.get("password", "")
        if not password or any(c in password for c in "\n\r\0"):
            raise Rejected("Password must be nonempty and contain no line breaks or NUL")
        fd = memory_fd(password.encode("utf-8") + b"\n")
        argv = ["/usr/bin/openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-iter", "100000",
                "-pass", "fd:" + str(fd)]
        argv += ["-d"] if algo == "aes-decrypt" else ["-salt"]
        exec_tool(argv, data, fd)
    elif algo in ("rsa-encrypt", "rsa-decrypt"):
        path = params.get("pubkey" if algo == "rsa-encrypt" else "privkey", "")
        fd = os.open(os.path.expanduser(path), os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as key_file:
            info = os.fstat(key_file.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_KEY_FILE:
                raise Rejected("RSA key must be a regular file of at most 64 KiB")
            key = key_file.read(MAX_KEY_FILE + 1)
        if len(key) > MAX_KEY_FILE:
            raise Rejected("RSA key exceeds 64 KiB")
        key_fd = memory_fd(key)
        argv = ["/usr/bin/openssl", "pkeyutl", "-inkey", "/proc/self/fd/" + str(key_fd)]
        argv += ["-encrypt", "-pubin"] if algo == "rsa-encrypt" else ["-decrypt", "-passin", "pass:"]
        exec_tool(argv, data, key_fd)
    elif algo in ("sha256", "sha512", "sha1", "md5"):
        exec_tool(["/usr/bin/openssl", "dgst", "-" + algo, "-binary"], data)
    elif algo in ("gzip", "gunzip"):
        exec_tool(["/usr/bin/gzip", "-9" if algo == "gzip" else "-d"], data)
    else:
        raise Rejected("Unknown algorithm")


def cancel(_signal, _frame):
    raise Rejected("Operation cancelled")


def main():
    harden()
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, cancel)
    mode = sys.argv[1:]
    deadline = time.monotonic() + (PASTE_TIMEOUT if mode == ["paste"] else TIMEOUT)
    if mode == ["--worker"]:
        worker(read_request(deadline))
        return
    if mode == ["paste"]:
        result = supervise(["/usr/bin/wl-paste", "--no-newline", "--type", "text/plain"],
                           b"", deadline)
    elif mode == ["step"]:
        raw = read_request(deadline)
        parse_request(raw)
        result = supervise([sys.executable, "-I", str(Path(__file__).resolve()), "--worker"],
                           raw, deadline)
    else:
        raise Rejected("Unknown operation")
    # Publish nothing until success, size checks AND process-group cleanup.
    # The helper-to-QML protocol is ASCII, so QML's character count is exact.
    os.set_blocking(1, False)
    output = base64.b64encode(result)
    offset = 0
    with selectors.SelectSelector() as sel:
        sel.register(1, selectors.EVENT_WRITE)
        while offset < len(output):
            for _, _ in sel.select(remaining(deadline)):
                offset += os.write(1, output[offset:offset + CHUNK])


if __name__ == "__main__":
    try:
        main()
    except Rejected as error:
        os.write(2, (str(error) + "\n").encode("ascii"))
        sys.exit(1)
    except Exception:
        # Never print tracebacks/exception values containing request contents.
        os.write(2, b"Operation failed (check input, parameters and dependencies)\n")
        sys.exit(1)
