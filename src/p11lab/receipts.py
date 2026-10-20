"""Atomic durable JSON records; no partial success receipt."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import sys
import tempfile


@contextmanager
def _preserve_failure_on_cleanup(cleanup, description):
    try:
        yield
    except BaseException as error:
        try:
            cleanup()
        except OSError as secondary:
            error.add_note(description + ': ' + str(secondary))
        raise
    else:
        cleanup()  # A cleanup-only failure is still a failed write.


def write_receipt(path: Path, record: dict) -> None:
    path = Path(path)
    temporary = None
    with _preserve_failure_on_cleanup(
        lambda: temporary.unlink(missing_ok=True) if temporary is not None else None,
        'Could not remove receipt temporary file',
    ):
        stream = tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=path.parent,
                                            prefix='.' + path.name + '-', delete=False)
        temporary = Path(stream.name)
        with _preserve_failure_on_cleanup(stream.close, 'Could not close receipt temporary file'):
            json.dump(record, stream, indent=2, sort_keys=True, allow_nan=False)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        if sys.platform == "linux":
            # Directory fsync needs os.O_DIRECTORY (POSIX-only); same platform
            # gate as bundle._sync_directory. File data is fsynced above on
            # every platform.
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            with _preserve_failure_on_cleanup(lambda: os.close(directory), 'Could not close receipt directory'):
                os.fsync(directory)
