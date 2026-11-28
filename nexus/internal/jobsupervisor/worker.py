"""Private per-run worker, launched by systemd rather than the SSH connection."""
import ctypes
import base64
import contextlib
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import tempfile

directory = Path(__file__).parent
request_file = directory / 'request.json'
request = json.loads(request_file.read_text())
request_file.unlink()
identity = {'id': request['id'], 'hash': request['hash']}


def status(**values):
    temporary = directory / 'status.new'
    descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, 'w') as file:
        json.dump({**identity, **values}, file)
        file.flush()
        os.fsync(file.fileno())
    os.replace(temporary, directory / 'status.json')


def main():
    # Reap double-forked/session-detached descendants too. Cgroup ownership and
    # cancellation remain systemd's responsibility, not PID/process-group guesses.
    if ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) != 0:
        status(state='worker_failed')
        return 1
    lock = threading.Lock()
    count = 0
    truncated = False
    output_error = False
    descriptor = os.open(directory / 'output', os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    output = os.fdopen(descriptor, 'wb', buffering=0)
    read_end, write_end = os.pipe()

    def capture():
        nonlocal count, truncated, output_error
        with os.fdopen(read_end, 'rb', buffering=0) as source:
            while True:
                data = source.read(8192)
                if not data:
                    break
                with lock:
                    remaining = max(0, 65536 - count)
                    truncated |= len(data) > remaining
                    if remaining:
                        try:
                            chunk = data[:remaining]
                            written = output.write(chunk)
                            count += written
                            output_error |= written != len(chunk)
                        except OSError:
                            output_error = True

    reader = threading.Thread(target=capture, daemon=True)
    reader.start()
    try:
        script = directory / 'command.sh'
        descriptor = os.open(script, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'wb') as file:
            file.write(request.pop('command').encode())
        status(state='running', startedAt=int(time.time()))
        with contextlib.ExitStack() as inputs:
            encoded_input = request.pop('input', '')
            child_input = subprocess.DEVNULL
            if encoded_input:
                payload = base64.b64decode(encoded_input, validate=True)
                if len(payload) > 98304:
                    raise ValueError('invalid private input')
                # Anonymous private descriptor: no named credential artifact,
                # pipe backpressure deadlock, inherited agent or environment.
                child_input = inputs.enter_context(tempfile.TemporaryFile(dir=directory))
                child_input.write(payload)
                child_input.seek(0)
                del payload, encoded_input
            process = subprocess.Popen(['/bin/sh', str(script)], stdin=child_input, stdout=write_end, stderr=write_end, cwd='/', env={'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/root', 'LANG': 'C.UTF-8', 'NEXUS_JOB_ID':request['id']})
        os.close(write_end)
        process.wait()
        while True:
            try:
                os.waitpid(-1, 0)
            except ChildProcessError:
                break
            except InterruptedError:
                continue
        reader.join()
        output.flush()
        os.fsync(output.fileno())
        output.close()
        script.unlink()
        code = process.returncode if process.returncode >= 0 else 128 - process.returncode
        status(state='complete', exitCode=code, truncated=truncated or output_error, outputError=output_error, finishedAt=int(time.time()))
        return min(code, 255)
    except Exception:
        # No exception, command, credentials or payload in the journal.
        status(state='worker_failed')
        return 1


try:
    sys.exit(main())
except Exception:
    sys.exit(1)
