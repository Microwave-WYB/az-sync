import atexit
import csv
import json
import sqlite3
import threading
from collections.abc import Iterable, Iterator
from importlib import resources
from itertools import batched
from pathlib import Path
from queue import Queue, ShutDown
from typing import Self

import httpx
from loguru import logger
from pydantic import BaseModel
from tqdm import tqdm
import ants

import az_sync.sql
from az_sync.utils import count_lines, gunzip, is_sha256


def consume[T](queue: Queue[T]) -> Iterator[T]:
    while True:
        try:
            yield queue.get()
        except ShutDown:
            break


class APKRecord(BaseModel):
    """APK record class represented as a dataclass."""

    sha256: str
    sha1: str
    md5: str
    dex_date: str
    apk_size: int
    pkg_name: str
    vercode: str
    vt_detection: str
    vt_scan_date: str
    dex_size: int
    markets: str

    @classmethod
    def row_factory(cls, cursor: sqlite3.Cursor, row: tuple) -> Self:
        dictvalues = dict(sqlite3.Row(cursor, row))
        return cls.model_validate(dictvalues)


class Metadata(BaseModel):
    pkg_name: str
    vercode: str
    data: str

    @classmethod
    def row_factory(cls, cursor: sqlite3.Cursor, row: tuple) -> Self:
        dictvalues = dict(sqlite3.Row(cursor, row))
        return cls.model_validate(dictvalues)


class AzConfig(BaseModel):
    """Configurations"""

    apikey: str
    max_workers: int = 40


class AzWorkspace:
    def __init__(self, workspace_path: Path) -> None:
        if workspace_path.is_file():
            raise ValueError("Workspace path must be a directory")
        self._dir = workspace_path
        workspace_path.mkdir(parents=True, exist_ok=True)
        if not self.config_path.exists():
            self.write_config(AzConfig(apikey="", max_workers=40))

    def write_config(self, conf: AzConfig) -> None:
        self.config_path.write_text(conf.model_dump_json(indent=2))

    @classmethod
    def search_workspace(cls, cwd: Path) -> Self | None:
        while cwd != cwd.root:
            if (cwd / ".az.json").exists():
                return cls(cwd)
            cwd = cwd.parent
        return None

    @property
    def config(self) -> AzConfig:
        return AzConfig.model_validate_json(self.config_path.read_text())

    @property
    def dir(self) -> Path:
        return self._dir

    @property
    def apk_list_path(self) -> Path:
        return self.dir / "apk.csv"

    @property
    def metadata_path(self) -> Path:
        return self.dir / "metadata.jsonl"

    @property
    def db_path(self) -> Path:
        return self.dir / "az.sqlite3"

    @property
    def config_path(self) -> Path:
        return self.dir / ".az.json"

    def fetch_apk_list(self) -> None:
        if self.apk_list_path.exists():
            print("APK list already exists.")
            return
        print("Fetching APK list...")
        ants.download_file(
            httpx.Request("GET", "https://androzoo.uni.lu/static/lists/latest.csv.gz"),
            output_dir=Path.cwd(),
            filename="apk.csv.gz",
        )
        print("Decompressing APK list...")
        gunzip(Path("apk.csv.gz"))

    def fetch_metadata(self, apikey: str) -> None:
        if Path(self.metadata_path).exists():
            print("APK metadata already exists.")
            return
        print("Fetching APK metadata...")
        ants.download_file(
            httpx.Request(
                "GET",
                "https://androzoo.uni.lu/api/get_gp_metadata_file/full",
                params=dict(apikey=apikey),
            ),
            output_dir=Path.cwd(),
            filename="metadata.jsonl.gz",
        )
        print("Decompressing APK metadata...")
        gunzip(Path("metadata.jsonl.gz"))


class AzDatabase:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path

        # Initialize the database
        self.conn = sqlite3.connect(self.db_path)
        cursor = self.conn.cursor()
        cursor.executescript(resources.read_text(az_sync.sql, "create_tables.sql"))
        self.conn.commit()

    def iter_records(self) -> Iterator[APKRecord]:
        """Iterate over the APK records in the database."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM apkrecord")
        batch_size = 1000
        while True:
            rows = cursor.fetchmany(batch_size)
            if not rows:
                break

            for row in rows:
                yield APKRecord.model_validate(dict(row))

    def iter_metadata(self) -> Iterator[Metadata]:
        """Iterate over the metadata records in the database."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM metadata")
        batch_size = 1000
        while True:
            rows = cursor.fetchmany(batch_size)
            if not rows:
                break

            for row in rows:
                yield Metadata.model_validate(dict(row))

    def search(self, pkg_name_or_sha256: str) -> list[APKRecord]:
        """Find APK records by package name."""
        self.conn.row_factory = APKRecord.row_factory
        cursor = self.conn.cursor()

        if "%" in pkg_name_or_sha256:
            cursor.execute(
                "SELECT * FROM apkrecord WHERE pkg_name LIKE ?",
                (f"%{pkg_name_or_sha256}%",),
            )
        elif is_sha256(pkg_name_or_sha256):
            cursor.execute("SELECT * FROM apkrecord WHERE sha256 = ?", (pkg_name_or_sha256,))
        else:
            cursor.execute("SELECT * FROM apkrecord WHERE pkg_name = ?", (pkg_name_or_sha256,))
        return cursor.fetchall()

    def metadata(
        self, pkg_name: str | None = None, vercode: int | None = None, contains: str | None = None
    ) -> Iterator[Metadata]:
        if not any([pkg_name, vercode, contains]):
            raise ValueError("At least one of pkg_name, vercode, or contains must be provided")
        self.conn.row_factory = Metadata.row_factory
        cursor = self.conn.cursor()

        conditions = []
        args = []

        # Build conditions and args lists
        if pkg_name is not None:
            conditions.append("pkg_name = ?")
            args.append(pkg_name)
        if vercode is not None:
            conditions.append("vercode = ?")
            args.append(vercode)
        if contains is not None:
            conditions.append("data LIKE ?")
            args.append(f"%{contains}%")

        # Combine conditions with AND
        stmt = "SELECT * FROM metadata WHERE " + " AND ".join(conditions)

        # Execute with the correct arguments
        cursor.execute(stmt, args)

        while results := cursor.fetchmany(100):
            yield from results

    def list_(self, offset: int = 0, limit: int = 100) -> list[APKRecord]:
        """List APK records in the database."""
        self.conn.row_factory = APKRecord.row_factory
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT * FROM apkrecord LIMIT ? OFFSET ?",
            (limit, offset),
        )
        return cursor.fetchall()

    def import_apk_list(self, apk_list_path: Path) -> None:
        """Import APK records from a CSV file."""
        total = count_lines(apk_list_path)

        pbar = tqdm(desc="Importing APK list", total=total)
        with open(apk_list_path, "r") as f:
            cursor = self.conn.cursor()

            reader = csv.DictReader(f)
            for batch in batched(reader, 50000):
                cursor.executemany(
                    resources.read_text(az_sync.sql, "insert_record.sql"),
                    [tuple(record.values()) for record in batch],
                )
                self.conn.commit()
                pbar.update(len(batch))

        print("\nImport completed.")

    def import_metadata(self, metadata_path: Path) -> None:
        """Import APK metadata from a JSONL file."""
        total_size = metadata_path.stat().st_size
        pbar = tqdm(
            desc="Importing APK metadata",
            total=total_size,
            unit="B",
            unit_scale=True,
            unit_divisor=1024,
        )
        with open(metadata_path, "r") as f:
            cursor = self.conn.cursor()

            for batch in batched(f, 3000):
                for line in batch:
                    data = json.loads(line)
                    pkg_name = data["docid"]
                    vercode = data["details"]["appDetails"]["versionCode"]
                    cursor.execute(
                        resources.read_text(az_sync.sql, "insert_metadata.sql"),
                        (pkg_name, vercode, line),
                    )
                    pbar.update(len(line))
                self.conn.commit()
            pbar.n = total_size

    def count(self) -> int:
        """Count the total number of APK records in the database."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM apkrecord")
        total = cursor.fetchone()[0]
        return total

    def __del__(self):
        self.conn.close()


class AzDownload:
    def __init__(
        self,
        apikey: str,
        out_dir: Path = Path("downloads"),
        max_workers: int = 40,
    ) -> None:
        self.apikey = apikey
        self.output_dir = Path(out_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.max_workers = max_workers
        self.download_queue = Queue[str](maxsize=max_workers)
        self.progress_queue = Queue[object]()
        self.lock = threading.Lock()
        self.client = httpx.Client(params=dict(apikey=apikey))

    def spawn_worker(self) -> threading.Thread:
        def worker() -> None:
            for sha256 in consume(self.download_queue):
                try:
                    self.download_single(sha256)
                except Exception as e:
                    logger.error(f"Error downloading {sha256}: {e}")

        return threading.Thread(target=worker)

    def spawn_pbar(self, total: int | None = None) -> threading.Thread:
        def worker() -> None:
            pbar = tqdm(total=total, desc="Downloading")
            for _ in consume(self.progress_queue):
                pbar.update()

        return threading.Thread(target=worker)

    def download_single(self, sha256: str) -> None:
        sha256 = sha256.strip().upper()
        if not is_sha256(sha256):
            raise ValueError(f"Invalid SHA256 hash: {sha256}")
        dest = self.output_dir / f"{sha256}.apk"
        dest_part = self.output_dir / f"{sha256}.apk.part"
        with self.lock:
            if dest.exists():
                logger.info(f"File {dest} already exists. Skipping download.")
                self.progress_queue.put(object())
                return
            if dest_part.exists():
                logger.info(f"File {dest_part} is being downloaded. Skipping download.")
                self.progress_queue.put(object())
                return
            dest_part.touch()
            atexit.register(lambda: dest_part.unlink(missing_ok=True))
        with self.client.stream(
            "GET", "https://androzoo.uni.lu/api/download", params=dict(sha256=sha256)
        ) as res:
            res.raise_for_status()
            with open(dest_part, "wb") as f:
                for chunk in res.iter_bytes():
                    f.write(chunk)
        with self.lock:
            dest_part.rename(dest)
            logger.info(f"File {dest} download completed.")
        self.progress_queue.put(object())

    def download_all(self, sha256s: Iterable[str]) -> None:
        download_threads = [self.spawn_worker() for _ in range(self.max_workers)]
        if not hasattr(sha256s, "__len__"):
            pbar_thread = self.spawn_pbar()
        else:
            pbar_thread = self.spawn_pbar(total=getattr(sha256s, "__len__")())
        try:
            pbar_thread.start()
            for thread in download_threads:
                thread.start()
            for sha256 in sha256s:
                sha256 = sha256.strip()
                self.download_queue.put(sha256)
            self.download_queue.shutdown()
            for thread in download_threads:
                thread.join()
            self.progress_queue.shutdown()
            pbar_thread.join()
        except KeyboardInterrupt:
            self.download_queue.shutdown(immediate=True)
            self.progress_queue.shutdown(immediate=True)
            for thread in download_threads:
                thread.join(timeout=0)
            pbar_thread.join(timeout=0)
            raise
