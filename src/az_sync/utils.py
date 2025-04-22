import re
from pathlib import Path
import subprocess
from queue import Queue, ShutDown
from typing import Iterator
import gzip


def count_lines(path: Path) -> int:
    """Count the number of lines in a file."""
    if not path.exists():
        raise FileNotFoundError(path)
    if not path.is_file():
        raise ValueError(f"{path} is not a file")
    lines = int(subprocess.check_output(["wc", "-l", str(path)]).split()[0])
    return lines


def consume[T](queue: Queue[T]) -> Iterator[T]:
    """Consume until a queue is shutdown"""
    try:
        while True:
            yield queue.get()
    except ShutDown:
        return


def gunzip(path: Path, out_path: Path | None = None) -> None:
    """Gunzip a file"""
    out_path = out_path or Path(str(path).removesuffix(".gz"))
    with gzip.open(path, "rb") as f_in, open(out_path, "wb") as f_out:
        while chunk := f_in.read(1024 * 1024):
            f_out.write(chunk)
            print(f"Written {len(chunk)} bytes", end="\r", flush=True)

    path.unlink()


def is_sha256(value: str) -> bool:
    """Check if a string is a valid SHA256 hash"""
    return re.match(r"^[a-fA-F0-9]{64}$", value) is not None
