"""Atomic durable JSON records; no partial success receipt."""
import json
import os
from pathlib import Path
import sys
import tempfile


def write_receipt(path: Path, record: dict) -> None:
    path = Path(path)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=path.parent,
                                         prefix='.' + path.name + '-', delete=False) as stream:
            temporary = Path(stream.name)
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
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
