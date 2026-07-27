#!/usr/bin/env python3
import errno
import os
import pty
import sys


pid, fd = pty.fork()
if pid == 0:
    os.execvpe(sys.argv[1], sys.argv[1:], os.environ)

payload = os.environ.get("PTY_INPUT")
if payload is not None:
    os.write(fd, payload.encode() + b"\n")

while True:
    try:
        data = os.read(fd, 4096)
    except OSError as error:
        if error.errno == errno.EIO:
            break
        raise
    if not data:
        break
    os.write(sys.stdout.fileno(), data)

_, status = os.waitpid(pid, 0)
sys.exit(os.waitstatus_to_exitcode(status))
