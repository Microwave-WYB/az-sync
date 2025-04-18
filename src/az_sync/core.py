import atexit
import sqlite3
import threading
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from queue import Queue, ShutDown

import httpx
import typer
from rich.progress import (
    BarColumn,
    DownloadColumn,
    Progress,
    TaskID,
    TextColumn,
    TimeRemainingColumn,
    TransferSpeedColumn,
)

client: httpx.Client = httpx.Client()


@atexit.register
def cleanup() -> None:
    """Close the HTTP client on exit."""
    client.close()


@dataclass
class APKRecord:
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


class AzDatabase:
    def __init__(self, db_path: Path | str = "/data/apk/apkindex.db") -> None:
        self.db_path = db_path

    def __iter__(self) -> Iterator[APKRecord]:
        """Iterate over the APK records in the database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM apkindex")
        for batch in cursor.fetchmany(100):
            for row in batch:
                yield APKRecord(
                    sha256=row[0],
                    sha1=row[1],
                    md5=row[2],
                    dex_date=row[3],
                    apk_size=row[4],
                    pkg_name=row[5],
                    vercode=row[6],
                    vt_detection=row[7],
                    vt_scan_date=row[8],
                    dex_size=row[9],
                    markets=row[10],
                )
        conn.close()

    def get(self, sha256: str) -> APKRecord | None:
        """Get an APK record by its SHA256 hash."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM apkindex WHERE sha256 = ?", (sha256,))
        row = cursor.fetchone()
        conn.close()
        if row:
            return APKRecord(
                sha256=row[0],
                sha1=row[1],
                md5=row[2],
                dex_date=row[3],
                apk_size=row[4],
                pkg_name=row[5],
                vercode=row[6],
                vt_detection=row[7],
                vt_scan_date=row[8],
                dex_size=row[9],
                markets=row[10],
            )
        return None

    def find(self, namelike: str) -> list[APKRecord]:
        """Find APK records by package name."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM apkindex WHERE pkg_name LIKE ?", (f"%{namelike}%",))
        rows = cursor.fetchall()
        conn.close()
        return [
            APKRecord(
                sha256=row[0],
                sha1=row[1],
                md5=row[2],
                dex_date=row[3],
                apk_size=row[4],
                pkg_name=row[5],
                vercode=row[6],
                vt_detection=row[7],
                vt_scan_date=row[8],
                dex_size=row[9],
                markets=row[10],
            )
            for row in rows
        ]


class AzSync:
    def __init__(
        self,
        apikey: str,
        db_path: Path | str = "/data/apk/apkindex.db",
        output_dir: Path | str = "/data/apk/downloads",
        max_workers: int = 40,
    ) -> None:
        self.apikey = apikey
        self.db = AzDatabase(db_path)
        self.output_dir = Path(output_dir)
        if not self.output_dir.exists():
            self.output_dir.mkdir(parents=True)
        self.max_workers = max_workers
        self.download_queue = Queue[APKRecord](maxsize=100)
        self.progress_queue = Queue[tuple[APKRecord, int]]()

    def progress(self) -> None:
        """Show progress of downloads."""
        tasks: dict[str, TaskID] = {}
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            DownloadColumn(),
            TransferSpeedColumn(),
            TimeRemainingColumn(),
        ) as self.pbar:
            while True:
                try:
                    record, downloaded = self.progress_queue.get()
                except ShutDown:
                    break
                if record.sha256 not in tasks:
                    tasks[record.sha256] = self.pbar.add_task(
                        description=f"Downloading {record.sha256}",
                        total=record.apk_size,
                    )
                self.pbar.update(
                    tasks[record.sha256],
                    completed=downloaded,
                )
                if self.pbar.tasks[tasks[record.sha256]].completed >= record.apk_size:
                    print(f"Downloaded {record.sha256}")
                    self.pbar.remove_task(tasks[record.sha256])
                    tasks.pop(record.sha256)

    def download_worker(self) -> None:
        """Download APK files."""
        while True:
            try:
                record = self.download_queue.get()
            except ShutDown:
                break
            with client.stream(
                "GET",
                "https://androzoo.uni.lu/api/download",
                params=dict(
                    sha256=record.sha256,
                ),
            ) as stream:
                part_path = self.output_dir / f"{record.sha256}.apk.part"
                with open(part_path, "wb") as f:
                    for chunk in stream.iter_bytes(1024 * 1024):
                        f.write(chunk)
                        self.progress_queue.put((record, len(chunk)))
                part_path.rename(part_path.with_suffix(".apk"))

    def download_preparation_worker(self) -> None:
        """Enqueue a record for download."""
        for record in self.db:
            self.download_queue.put(record)
        self.download_queue.shutdown()

    def run(self) -> None:
        progress_thread = threading.Thread(target=self.progress, daemon=True)
        progress_thread.start()
        download_preparation_thread = threading.Thread(
            target=self.download_preparation_worker, daemon=True
        )
        download_preparation_thread.start()
        for _ in range(self.max_workers):
            download_thread = threading.Thread(target=self.download_worker, daemon=True)
            download_thread.start()

        download_preparation_thread.join()
        self.download_queue.join()
        self.progress_queue.shutdown()
        self.progress_queue.join()


def sync(
    apikey: str = typer.Argument(..., help="Androzoo API key"),
    db_path: str = typer.Option("/data/apk/apkindex.db", help="Path to the APK database"),
    output_dir: str = typer.Option(
        "/data/apk/downloads", help="Directory to save downloaded APK files"
    ),
    max_workers: int = typer.Option(40, help="Number of concurrent download workers"),
) -> None:
    """Sync APK files from Androzoo."""
    az_sync = AzSync(apikey, db_path, output_dir, max_workers)
    az_sync.run()
