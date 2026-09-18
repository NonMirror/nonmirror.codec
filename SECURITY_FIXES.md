# Codec security fixes — 1.0.1

This change addresses the three blockers reported in the
[marketplace review](https://github.com/omacom/omarchy-plugin-marketplace/issues/7001#issuecomment-5694640610)
of commit `202270ebd9527e4f838858fac5a5cbdf9a79dccf`. It also fixes the same
credential-exposure pattern in the clipboard copy path.

## 1. Private data and passwords in process arguments

**How it worked.** QML started Bash with the base64 input and every algorithm
parameter as positional arguments. For password-based AES, Bash then started
OpenSSL with `-pass pass:<password>`. Raw-key AES used `-K <key> -iv <iv>`.
Copying a result also supplied that result as a Bash argument.

Process arguments can be inspected through tools such as `ps` and, subject
to the system's access controls, `/proc/<pid>/cmdline`. A local observer could
capture a password, raw key, plaintext, ciphertext or copied result while the
process was running. Base64 is reversible encoding, so encoding private data
did not protect it. Correct shell quoting prevented injection but did not
prevent this disclosure.

**Fix.** `BoundedProcess.qml` starts a fixed Python command and writes a bounded
JSON request to its stdin. The request contains the algorithm ID, base64 bytes
and parameters. `Algorithms.js` no longer supplies Bash scripts.

- Password-based AES reads its password using OpenSSL's `-pass fd:<number>`.
- Raw-key AES uses Python `cryptography`'s AES-CBC and PKCS#7 APIs, keeping the
  key and IV inside the worker. There is no production `-K`/`-iv` command.
- RSA key paths arrive over stdin. Only regular files up to 64 KiB are read;
  their contents are passed using an anonymous descriptor. OpenSSL receives
  `/proc/self/fd/<number>`, not the user's key pathname.
- Payloads passed to OpenSSL/gzip use stdin backed by an anonymous, mode-0600
  Linux memory file. These descriptors have no shared filesystem pathname;
  only the descriptors needed by the command survive `exec`.
- Clipboard copy writes text to `wl-copy` through stdin. A fixed `timeout`
  command bounds its initial handoff to 3 seconds, with a 1-second kill grace.
  After a successful handoff, wl-copy's normal clipboard owner stays alive
  to serve the copied selection.

Neither credentials nor transformed data are placed in descendant arguments
or added to environment variables. Child diagnostics are counted and discarded
instead of being displayed or logged, since diagnostics may also reveal private
data. Helper errors use fixed messages and core dumps are disabled.

This removes the process-argument disclosure. It does not protect secrets from
root or an attacker permitted to read this user's process memory/descriptors.
The QML fields and worker necessarily hold data in memory; this is not a
secure-erasure guarantee.

## 2. An unlimited clipboard stream could exhaust the desktop shell's memory

**How it worked.** A clipboard owner controls the bytes returned to `wl-paste`.
It could send a huge stream or keep the transfer open indefinitely. The old
`StdioCollector` retained everything until EOF without a byte limit or deadline.
Because Codec stays loaded inside `omarchy-shell`, accumulating this data could
freeze or terminate the desktop shell, not just the popup.

**Fix.** The Python supervisor now launches `wl-paste` in a separate process
group and drains stdout/stderr in bounded chunks. It allows at most 256 KiB of
clipboard bytes and 3 seconds for the operation. A one-byte lookahead detects
overflow, including a producer without newline delimiters. Each incoming chunk
is checked before being appended to the bounded byte array.

The helper emits base64 only after the producer has succeeded and cleanup has
finished. QML uses `SplitParser` with an empty delimiter, which delivers chunks
without collecting an unfinished line. QML independently checks each chunk
before concatenating it. The target field's remaining UTF-8 byte capacity is
checked before pasted text is appended. Failed or oversized transfers insert
nothing; changing fields or closing the overlay cancels pending reads.

## 3. CLI output and decompression could grow without bounds

**How it worked.** Each Bash pipeline could emit unlimited stdout/stderr and
run indefinitely. A small gzip input can represent far more decompressed data
than its compressed size. Running Gunzip on such input sent the expanded bytes
through base64 into an unbounded QML collector. Limiting only compressed input,
or checking size after process exit, cannot stop that growth.

This finding concerns resource exhaustion and availability. The review did not
identify a buffer-overflow primitive or demonstrate arbitrary code execution.

**Fix.** Every external transform runs under `codec_runner.py` supervision:

| Resource | Limit / behavior |
| --- | --- |
| Input and each step's raw output | 256 KiB |
| JSON request, including encoded data and parameters | 384 KiB |
| Individual parameter | 4 KiB of UTF-8 |
| RSA key file | Regular file, at most 64 KiB |
| Child stderr | 4 KiB, counted but never forwarded |
| CLI operation | 10 seconds, including request reading and result delivery |
| Clipboard read | 3 seconds |
| Helper/worker address space and CPU | 256 MiB virtual address space; 10 CPU seconds |
| QML stdout/stderr | 349,528 base64 characters / 4,096 ASCII characters |
| QML fallback watchdog | 12 seconds; signals the supervisor to clean up |

The supervisor concurrently writes stdin and drains both output pipes, so a
child cannot deadlock it by filling stderr while it waits for input. Raw output
is counted **before base64 encoding**, including gzip expansion. No partial
result is published on overflow, timeout, invalid data or command failure.

Each worker starts a new session/process group. On failure or cancellation,
the supervisor sends SIGKILL to the entire worker group, waits for its direct
child, and reaps adopted descendants using Linux's child-subreaper facility.
Cleanup also runs after success, so background descendants cannot survive a
finished transform. It still targets the group when the leader has already
exited. SIGKILL prevents a child that ignores SIGTERM from defeating cleanup.
Cancellation is masked during spawn until cleanup owns the child. The direct
worker also receives a parent-death kill signal if the supervisor disappears.

QML waits for cleanup before permitting reuse of a busy runner. Session checks
discard callbacks from an older overlay session. Native transform outputs also
have a size limit; a pipeline has at most 32 steps, and quadratic Base58/radix
conversions and live calculator input are restricted to 4 KiB.

## Compatibility and verification

Version 1.0.1 adds `python` and `python-cryptography` runtime dependencies.
Password-based AES remains on OpenSSL with PBKDF2 and 100,000 iterations.
Raw-key AES remains AES-256-CBC with PKCS#7 padding; tests compare its output
against OpenSSL for a public test vector. Passwords containing line breaks or
NUL are rejected instead of silently being truncated by OpenSSL's line reader.
Oversized or slow jobs now fail with a bounded error instead of continuing.

Run the regression suite with:

```sh
python3 -m unittest discover -s tests -v
```

The tests use synthetic inputs and disposable processes. They cover:

- Binary hashing and exact input/output boundaries.
- AES password/raw-key round trips, raw AES/OpenSSL compatibility, RSA round
  trips, oversized key files and FIFO rejection.
- Oversized/malformed requests and a caller that never finishes stdin.
- A gzip expansion bomb, corrupt/truncated gzip and suppression of partial output.
- Endless stdout, endless stderr, a stalled producer, cancellation and an exited
  wrapper whose child retains the pipes. Child PIDs must disappear from `/proc`,
  proving both termination and reaping rather than leaving zombies.
- Live `/proc` sampling during AES operations: synthetic secrets and base64
  payloads must be absent from supervisor/worker arguments; OpenSSL must use `fd:`.
- The actual offscreen Quickshell bridge: repeated stdin requests, byte-boundary
  collector checks and cancellation without publishing stale results.

Marketplace validation and its automated security baseline must be refreshed
for the exact pushed commit. Those results do not replace the maintainer's
manual review of these fixes.

Implementation references: [Python subprocess pipes and process sessions](https://docs.python.org/3/library/subprocess.html),
[Quickshell stream parser implementation](https://github.com/quickshell-mirror/quickshell/blob/master/src/io/datastream.cpp),
and [cryptography symmetric encryption APIs](https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/).
