"""Security regressions run in disposable processes, using synthetic data only."""

import base64
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "codec_runner.py"
spec = importlib.util.spec_from_file_location("runner", RUNNER)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def request(algo, data=b"hello", params=None):
    return json.dumps({"id": algo, "data": base64.b64encode(data).decode(),
                       "params": params or {}}).encode()


def call(algo, data=b"hello", params=None):
    return subprocess.run([sys.executable, "-I", str(RUNNER), "step"],
                          input=request(algo, data, params), capture_output=True, timeout=15)


class RunnerTests(unittest.TestCase):
    def decode(self, result):
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, b"")
        return base64.b64decode(result.stdout, validate=True)

    def test_hashes_binary_and_maximum_input(self):
        data = bytes(range(256)) * 1024
        for algo in ("sha256", "sha512", "sha1", "md5"):
            with self.subTest(algo=algo):
                self.assertEqual(self.decode(call(algo, data)), hashlib.new(algo, data).digest())

    def test_gzip_and_output_boundary(self):
        for size in (0, runner.MAX_DATA):
            data = b"x" * size
            compressed = self.decode(call("gzip", data))
            self.assertEqual(gzip.decompress(compressed), data)
            self.assertEqual(self.decode(call("gunzip", compressed)), data)
        rejected = call("gunzip", gzip.compress(b"x" * (runner.MAX_DATA + 1)))
        self.assertNotEqual(rejected.returncode, 0)
        self.assertEqual(rejected.stdout, b"")
        self.assertIn(b"Output exceeds", rejected.stderr)

    def test_compression_bomb_and_invalid_gzip_publish_nothing(self):
        for data in (gzip.compress(b"x" * (32 * 1024 * 1024)), b"invalid gzip",
                     gzip.compress(b"secret plaintext")[:-3]):
            result = call("gunzip", data)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b"")

    def test_aes_password_and_raw_key_roundtrips(self):
        data = bytes(range(256)) + b"\0binary\n"
        for prefix, params in (("aes", {"password": "synthetic-密碼-'$()"}),
                               ("aes-key", {"key": "12" * 32, "iv": "34" * 16})):
            encrypted = self.decode(call(prefix + "-encrypt", data, params))
            self.assertEqual(self.decode(call(prefix + "-decrypt", encrypted, params)), data)
        encrypted = self.decode(call("aes-encrypt", data, {"password": "correct"}))
        bad = call("aes-decrypt", encrypted, {"password": "wrong"})
        self.assertNotEqual(bad.returncode, 0)
        self.assertEqual(bad.stdout, b"")

    def test_raw_aes_openssl_compatibility(self):
        # Test-only public vector; production never uses the -K/-iv interface.
        params = {"key": "00" * 32, "iv": "00" * 16}
        expected = subprocess.run(["openssl", "enc", "-aes-256-cbc", "-nosalt",
                                   "-K", params["key"], "-iv", params["iv"]],
                                  input=b"hello", capture_output=True, check=True).stdout
        self.assertEqual(self.decode(call("aes-key-encrypt", b"hello", params)), expected)

    def test_rsa_roundtrip_and_file_limits(self):
        with tempfile.TemporaryDirectory() as tmp:
            private, public = Path(tmp) / "private.pem", Path(tmp) / "public.pem"
            subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt",
                            "rsa_keygen_bits:2048", "-out", str(private)], capture_output=True, check=True)
            subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)],
                           capture_output=True, check=True)
            ciphertext = self.decode(call("rsa-encrypt", b"hello", {"pubkey": str(public)}))
            self.assertEqual(self.decode(call("rsa-decrypt", ciphertext, {"privkey": str(private)})), b"hello")
            public.write_bytes(b"x" * (runner.MAX_KEY_FILE + 1))
            self.assertNotEqual(call("rsa-encrypt", params={"pubkey": str(public)}).returncode, 0)
            fifo = Path(tmp) / "fifo"
            os.mkfifo(fifo)
            self.assertNotEqual(call("rsa-encrypt", params={"pubkey": str(fifo)}).returncode, 0)

    def test_invalid_and_oversized_requests(self):
        cases = [request("sha256", b"x" * (runner.MAX_DATA + 1)),
                 request("aes-encrypt", params={"password": "x" * (runner.MAX_PARAM + 1)}),
                 b"x" * (runner.MAX_REQUEST + 1), b"{" * 5000,
                 request("not-allowed"), request("aes-encrypt", params={"password": "a\nb"}),
                 b'{"id":"sha256","data":"%%%","params":{}}']
        for raw in cases:
            result = subprocess.run([sys.executable, "-I", str(RUNNER), "step"],
                                    input=raw, capture_output=True, timeout=15)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b"")
            self.assertLessEqual(len(result.stderr), runner.MAX_STDERR)

    def test_request_deadline(self):
        # The real deadline includes a caller that never finishes stdin.
        with subprocess.Popen([sys.executable, "-I", str(RUNNER), "step"],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc:
            proc.stdin.write(b'{"id":')
            proc.stdin.flush()
            proc.wait(timeout=12)
            self.assertEqual(proc.stdout.read(), b"")
            self.assertIn(b"timed out", proc.stderr.read())

    def test_secrets_absent_from_live_descendant_arguments(self):
        data = b"SYNTHETIC_PRIVATE_INPUT_4f729ac" * 4000
        password = "SYNTHETIC_PASSWORD_d123fa9"
        key, iv = "b1" * 32, "c2" * 16
        forbidden = [data[:27], base64.b64encode(data)[:64], password.encode(), key.encode(), iv.encode()]
        commands = []
        for algo, params in (("aes-encrypt", {"password": password}),
                             ("aes-key-encrypt", {"key": key, "iv": iv})):
            with tempfile.TemporaryFile() as source, tempfile.TemporaryFile() as output:
                source.write(request(algo, data, params))
                source.seek(0)
                with subprocess.Popen([sys.executable, "-I", str(RUNNER), "step"],
                                      stdin=source, stdout=output, stderr=subprocess.PIPE) as proc:
                    while proc.poll() is None:
                        try:
                            children = Path(f"/proc/{proc.pid}/task/{proc.pid}/children").read_text().split()
                            for pid in [str(proc.pid)] + children:
                                argv = Path(f"/proc/{pid}/cmdline").read_bytes()
                                commands.append(argv)
                                for secret in forbidden:
                                    self.assertNotIn(secret, argv)
                        except FileNotFoundError:
                            pass
                        time.sleep(0.001)
                    self.assertEqual(proc.returncode, 0, proc.stderr.read())
        self.assertTrue(any(b"openssl\0enc" in cmd for cmd in commands), commands)
        self.assertTrue(any(b"-pass\0fd:" in cmd for cmd in commands))
        self.assertFalse(any(b"bash\0" in cmd for cmd in commands))

    def exercise_producer(self, behavior, expected, cancel=False, close_child_pipes=False):
        # These fixtures replace the producer behind the SAME supervisor used
        # for wl-paste and CLI steps; no real desktop clipboard is touched.
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            pidfile = tmp / "pids"
            producer = tmp / "producer.py"
            producer.write_text('''import os, signal, sys, time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
child = os.fork()
if child == 0:
    if sys.argv[2] == "closed": os.close(1); os.close(2)
    while True: time.sleep(1)
with open(sys.argv[1], "w") as f: f.write(str(os.getpid()) + " " + str(child))
''' + behavior)
            harness = tmp / "harness.py"
            harness.write_text(f'''import sys, time, signal
sys.path.insert(0, {str(ROOT)!r})
import codec_runner as r
signal.signal(signal.SIGTERM, r.cancel)
try:
    data = r.supervise([sys.executable, {str(producer)!r}, {str(pidfile)!r}, {"closed" if close_child_pipes else "open"!r}], b"", time.monotonic() + 0.5)
    sys.stdout.buffer.write(data)
except r.Rejected as e:
    print(str(e), file=sys.stderr)
    sys.exit(1)
''')
            with subprocess.Popen([sys.executable, str(harness)], stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE) as proc:
                if cancel:
                    end = time.monotonic() + 3
                    while not pidfile.exists() and time.monotonic() < end:
                        time.sleep(0.005)
                    proc.send_signal(signal.SIGTERM)
                stdout, stderr = proc.communicate(timeout=4)
            self.assertEqual(stdout, b"")
            if expected:
                self.assertNotEqual(proc.returncode, 0)
                self.assertIn(expected, stderr)
            else:
                self.assertEqual(proc.returncode, 0, stderr)
            pids = pidfile.read_text().split()
            self.assertEqual(len(pids), 2)
            for pid in pids:
                self.assertFalse(Path("/proc", pid).exists(), "Producer was not terminated AND reaped")

    def test_endless_stdout_cleanup(self):
        self.exercise_producer('while True: os.write(1, b"x" * 8192)\n', b"Output exceeds")

    def test_endless_stderr_cleanup(self):
        self.exercise_producer('while True: os.write(2, b"x" * 8192)\n', b"Error output exceeds")

    def test_timeout_cleanup(self):
        self.exercise_producer('while True: time.sleep(1)\n', b"timed out")

    def test_cancel_cleanup(self):
        self.exercise_producer('while True: time.sleep(1)\n', b"cancelled", cancel=True)

    def test_exited_leader_with_open_descendant_pipes(self):
        self.exercise_producer('sys.exit(0)\n', b"timed out")

    def test_success_cleans_descendants_with_closed_pipes(self):
        self.exercise_producer('sys.exit(0)\n', None, close_child_pipes=True)


if __name__ == "__main__":
    unittest.main()
