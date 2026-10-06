"""Bounded regular-file credential intake, shared by every runner path."""
import os
import stat


def _read_secret_file(path) -> bytes:
    # Nonblocking open matters: fstat alone cannot protect a blocking FIFO open.
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError('credential file must be a regular file')
        with os.fdopen(fd, 'rb') as stream:
            fd = None
            data = stream.read(4097)
        if len(data) > 4096:
            raise ValueError('credential input exceeds 4096-byte bound')
        return data
    finally:
        if fd is not None:
            os.close(fd)


def credential_text(data: bytes, *, file: bool) -> str:
    """A PIN is one nonempty UTF-8 line; one file LF is framing."""
    if file and data.endswith(b'\n'):
        data = data[:-1]
    if not data:
        raise ValueError('credential input is empty')
    if any(byte in data for byte in (b'\n', b'\r', b'\0')):
        raise ValueError('credential input must be exactly one text line')
    try:
        return data.decode('utf-8', 'strict')
    except UnicodeDecodeError:
        # Never include decoder exception data, which can contain the secret.
        raise ValueError('credential input must be valid UTF-8') from None


def snapshot_credentials(inputs: dict, descriptor: dict) -> tuple[dict, list[str]]:
    """Snapshot files before writable resources; preserve absent/empty scalars."""
    credentials, secrets = {}, []
    for key, value in inputs.items():
        if descriptor['inputs'].get(key, {}).get('secret'):
            data = _read_secret_file(value) if key.endswith('_FILE') else value.encode()
            if len(data) > 4096:
                raise ValueError('credential input exceeds 4096-byte bound')
            # Empty scalar inputs remain explicit; adapters decide whether required.
            text = credential_text(data, file=key.endswith('_FILE')) if data or key.endswith('_FILE') else ''
            credentials[key] = data
            if text:
                secrets.append(text)
    return credentials, secrets
