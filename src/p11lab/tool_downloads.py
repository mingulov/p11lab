"""Bounded opaque acquisition for already-authorized installed tool records."""
import hashlib
from functools import partial
from http.client import HTTPConnection, HTTPException, HTTPResponse, HTTPSConnection, NotConnected
import io
import os
from pathlib import Path
import stat
import socket
import time
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from .tool_inputs import ToolInputError, _LIMITS, _file, _require


def safe_directory(path: Path) -> None:
    """Do not traverse an existing link or non-directory, including the root."""
    path = Path(path).absolute()
    for entry in [*reversed(path.parents), path]:
        try:
            mode = entry.lstat().st_mode
        except FileNotFoundError:
            continue
        _require(stat.S_ISDIR(mode), 'unsafe acquisition directory')


def _target(url):
    parsed = urlsplit(url)
    _require(parsed.scheme == 'https' and parsed.netloc == 'snapshot.debian.org'
             and not parsed.query and not parsed.fragment
             and (parsed.path.startswith('/archive/') or parsed.path.startswith('/file/'))
             and not any(c.isspace() or ord(c) < 32 for c in url), 'unapproved redirect URL/origin')


def _remaining(deadline):
    left = deadline - time.monotonic()
    _require(left > 0, 'tool input acquisition deadline exceeded')
    return min(_LIMITS['io_seconds'], left)


class _DeadlineReader(io.RawIOBase):
    """Enforce time below HTTP status/header/chunk/trailer buffered loops."""
    def __init__(self, stream, sock, deadline):
        self.stream, self.sock, self.deadline = stream, sock, deadline

    def readable(self):
        return True

    def readinto(self, buffer):
        try:
            self.sock.settimeout(_remaining(self.deadline))
            data = self.stream.read1(len(buffer))  # At most one underlying read.
            _remaining(self.deadline)
            buffer[:len(data)] = data
            return len(data)
        except BaseException as error:
            # Leave this adapter open until HTTPResponse.close() flushes its
            # wrapper; closing it here would mask the deadline with ValueError.
            try:
                self.stream.close()
            except OSError as cleanup:
                error.add_note('Could not close failed HTTP input stream: ' + str(cleanup))
            if isinstance(error, ToolInputError):
                # http.client interprets ValueError as malformed chunk length.
                # Use an I/O timeout so that framing cannot swallow our budget.
                raise TimeoutError(str(error)) from error
            raise

    def close(self):
        try:
            self.stream.close()
        finally:
            super().close()


class _DeadlineResponse(HTTPResponse):
    def __init__(self, sock, *args, deadline, **kwargs):
        super().__init__(sock, *args, **kwargs)
        self.fp = io.BufferedReader(_DeadlineReader(self.fp, sock, deadline))


class _Connection(HTTPSConnection):
    """The bounded GET transport, retaining stdlib TLS/proxy setup."""
    def __init__(self, host, *, deadline, **kwargs):
        super().__init__(host, **kwargs)
        self.deadline = deadline
        self._create_connection = self._connect_socket
        self.response_class = partial(_DeadlineResponse, deadline=deadline)

    def _connect_socket(self, address, _timeout, source_address):
        _remaining(self.deadline)
        # Blocking DNS cannot be preempted here. Recheck before opening any
        # socket after it returns, and give each address only remaining time.
        addresses = socket.getaddrinfo(*address, 0, socket.SOCK_STREAM)
        last_error = None
        for family, kind, protocol, _, endpoint in addresses:
            _remaining(self.deadline)
            candidate = None
            try:
                candidate = socket.socket(family, kind, protocol)
                if source_address:
                    candidate.bind(source_address)
                candidate.settimeout(_remaining(self.deadline))
                candidate.connect(endpoint)
                _remaining(self.deadline)
                return candidate
            except BaseException as error:
                if candidate is not None:
                    try:
                        candidate.close()
                    except OSError as cleanup:
                        error.add_note('Could not close failed HTTP connection: ' + str(cleanup))
                if not isinstance(error, OSError):
                    raise
                last_error = error
                _remaining(self.deadline)
        _remaining(self.deadline)
        if last_error is not None:
            raise last_error
        raise OSError('HTTP origin resolved to no addresses')

    def connect(self):
        _remaining(self.deadline)
        # This retains stdlib TCP_NODELAY, CONNECT and connection audit events.
        HTTPConnection.connect(self)
        self.sock.settimeout(_remaining(self.deadline))
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self._tunnel_host or self.host)
        _remaining(self.deadline)

    def send(self, data):
        # Our GET and CONNECT requests have bytes-only headers, never a
        # caller-provided file/iterable body with its own hidden send loop.
        _require(isinstance(data, (bytes, bytearray, memoryview)), 'unsupported HTTP request body')
        _remaining(self.deadline)
        if self.sock is None:
            if not self.auto_open:
                raise NotConnected()
            self.connect()
        self.sock.settimeout(_remaining(self.deadline))
        super().send(data)
        _remaining(self.deadline)


class _HTTPS(HTTPSHandler):
    def __init__(self, deadline):
        super().__init__()  # Preserve default certificate/hostname verification.
        self.deadline = deadline

    def https_open(self, request):
        return self.do_open(partial(_Connection, deadline=self.deadline), request, context=self._context)


class _Redirects(HTTPRedirectHandler):
    def __init__(self, deadline):
        self.hops = 0
        self.deadline = deadline

    def http_error_302(self, req, fp, code, msg, headers):
        # urllib normally drains the entire redirect body with read(), which
        # can hide unlimited slow progress. These GET requests need no body.
        fp.close()
        return super().http_error_302(req, io.BytesIO(), code, msg, headers)

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _target(newurl)  # Must happen before urllib follows the target.
        # urllib's http_error_302 reuses the old request's timeout when opening
        # the redirect. Tighten that value, not only our deadline check.
        req.timeout = min(getattr(req, 'timeout', _LIMITS['io_seconds']), _remaining(self.deadline))
        self.hops += 1
        _require(self.hops <= _LIMITS['redirects'], 'tool input redirect limit exceeded')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download_locked_file(record: dict, destination: Path, *, deadline: float | None = None) -> dict:
    """Retain original opaque bytes; never extract, execute, cache or retry them.

    The trusted caller selects a packaged record. The size/hash below do not make
    an arbitrary caller-supplied record authoritative for a later build.
    """
    try:
        return _download_locked_file(record, destination, deadline=deadline)
    except HTTPException as error:
        raise ToolInputError('invalid tool input HTTP response: ' + str(error)) from error


def _download_locked_file(record, destination, *, deadline):
    _file(record)
    _target(record['url'])
    started = time.monotonic()
    deadline = min(deadline, started + _LIMITS['payload_seconds']) if deadline is not None else started + _LIMITS['payload_seconds']
    destination = Path(destination).absolute()
    safe_directory(destination.parent)
    destination.parent.mkdir(parents=True, exist_ok=True)
    partial = destination.with_name(destination.name + '.part')
    _require(not destination.exists() and not destination.is_symlink()
             and not partial.exists() and not partial.is_symlink(), 'acquisition destination must be fresh')
    # Exclusive creation also rejects a racing pre-existing .part or symlink.
    descriptor = os.open(partial, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    count = 0
    digest = hashlib.sha256()
    with os.fdopen(descriptor, 'wb') as output:
        opener = build_opener(_Redirects(deadline), _HTTPS(deadline))
        request = Request(record['url'], headers={'Accept-Encoding': 'identity', 'User-Agent': 'p11lab-tool-inputs/1'})
        with opener.open(request, timeout=_remaining(deadline)) as response:
            _target(response.geturl())
            _require(response.headers.get('Content-Encoding', 'identity').lower() == 'identity', 'unexpected input encoding')
            size = response.headers.get('Content-Length')
            _require(size is None or size == str(record['size']), 'input Content-Length mismatch')
            while True:
                _remaining(deadline)
                # HTTP framing itself can loop, so _DeadlineReader enforces the
                # budget beneath those loops as well as this payload boundary.
                chunk = response.read1(min(64 * 1024, record['size'] + 1 - count))
                _remaining(deadline)
                if not chunk:
                    break
                count += len(chunk)
                _require(count <= record['size'], 'input exceeds exact size')
                digest.update(chunk)
                output.write(chunk)
            _require(count == record['size'] and digest.hexdigest() == record['sha256'], 'input checksum/size mismatch')
            final_url = response.geturl()
        output.flush()
        os.fsync(output.fileno())
    _remaining(deadline)
    safe_directory(destination.parent)
    # Atomic non-overwriting promotion, unlike replace() which can overwrite a
    # file created after the initial fresh-destination check.
    os.link(partial, destination, follow_symlinks=False)
    partial.unlink()
    return {'size': count, 'sha256': digest.hexdigest(), 'final_url': final_url}
