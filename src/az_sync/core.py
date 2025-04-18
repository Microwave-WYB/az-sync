import atexit
import json
import sqlite3
import subprocess
import threading
from collections.abc import Iterator
from dataclasses import asdict, dataclass
from pathlib import Path
from queue import Queue, ShutDown
from typing import Any, List, Optional

import httpx
import pandas as pd
import rich
import typer
from loguru import logger
from rich.progress import (
    BarColumn,
    DownloadColumn,
    Progress,
    TaskID,
    TextColumn,
    TimeRemainingColumn,
    TransferSpeedColumn,
)

logger.add(
    "logs/sync.log",
    rotation="10 MB",
)
client: httpx.Client = httpx.Client()
app = typer.Typer(
    help="Sync APK files from Androzoo.",
)


@atexit.register
def cleanup() -> None:
    """Close the HTTP client on exit."""
    client.close()


@dataclass(repr=True)
class APKRecord:
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
    def from_dict(cls, data: dict[str, Any]) -> "APKRecord":
        """Create an APKRecord from a dictionary."""
        return cls(
            sha256=data.get("sha256", ""),
            sha1=data.get("sha1", ""),
            md5=data.get("md5", ""),
            dex_date=data.get("dex_date", ""),
            apk_size=int(data.get("apk_size", 0)),
            pkg_name=data.get("pkg_name", ""),
            vercode=str(data.get("vercode", "")),
            vt_detection=str(data.get("vt_detection", "")),
            vt_scan_date=data.get("vt_scan_date", ""),
            dex_size=int(data.get("dex_size", 0)),
            markets=data.get("markets", ""),
        )


class AzDatabase:
    def __init__(self, db_path: Path | str = "/data/apk/apkindex.db") -> None:
        self.db_path = Path(db_path)
        if self.db_path.is_dir():
            self.db_path = self.db_path / "apkindex.db"

        # Initialize the database
        self._init_db()

    def _init_db(self) -> None:
        """Initialize the database with the APK records table."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Create the table if it doesn't exist
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS apkrecord (
            sha256 TEXT PRIMARY KEY,
            sha1 TEXT,
            md5 TEXT,
            dex_date TEXT,
            apk_size INTEGER,
            pkg_name TEXT,
            vercode TEXT,
            vt_detection TEXT,
            vt_scan_date TEXT,
            dex_size INTEGER,
            markets TEXT
        )
        """)

        conn.commit()
        conn.close()

    def __iter__(self) -> Iterator[APKRecord]:
        """Iterate over the APK records in the database."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Fetch records in batches to conserve memory
        cursor.execute("SELECT * FROM apkrecord")
        batch_size = 1000
        while True:
            rows = cursor.fetchmany(batch_size)
            if not rows:
                break

            for row in rows:
                record_dict = dict(row)
                yield APKRecord.from_dict(record_dict)

        conn.close()

    def get(self, sha256: str) -> Optional[APKRecord]:
        """Get an APK record by its SHA256 hash."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM apkrecord WHERE sha256 = ?", (sha256,))
        row = cursor.fetchone()

        conn.close()

        if row:
            return APKRecord.from_dict(dict(row))
        return None

    def search(self, namelike: str) -> List[APKRecord]:
        """Find APK records by package name."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        if "%" in namelike:
            cursor.execute("SELECT * FROM apkrecord WHERE pkg_name LIKE ?", (f"%{namelike}%",))
        else:
            cursor.execute("SELECT * FROM apkrecord WHERE pkg_name = ?", (namelike,))
        rows = cursor.fetchall()

        conn.close()

        return [APKRecord.from_dict(dict(row)) for row in rows]

    def import_csv(self, csv_path: Path | str) -> None:
        """Import APK records from a CSV file."""
        total = (
            int(
                subprocess.check_output(
                    ["wc", "-l", csv_path],
                    text=True,
                ).split()[0]
            )
            - 1
        )
        current = 0

        conn = sqlite3.connect(self.db_path)

        for chunk in pd.read_csv(
            csv_path,
            chunksize=10000,
            dtype={
                "vercode": str,
                "vt_detection": str,
                "sha256": str,
                "sha1": str,
                "md5": str,
                "pkg_name": str,
                "dex_date": str,
                "vt_scan_date": str,
                "markets": str,
            },
            na_values=["NA", "N/A", ""],
            keep_default_na=False,
        ):
            # Fill NA values with empty strings
            chunk = chunk.fillna("")

            chunk.to_sql(
                "apkrecord", conn, if_exists="append", index=False, method="multi", chunksize=1000
            )

            current += len(chunk)
            print(f"Imported {current:,}/{total:,} records", end="\r", flush=True)

        conn.commit()
        conn.close()
        print("\nImport completed.")


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
                    apikey=self.apikey,  # Added apikey to the parameters
                ),
            ) as stream:
                part_path = self.output_dir / f"{record.sha256}.apk.part"
                with open(part_path, "wb") as f:
                    for chunk in stream.iter_bytes(1024 * 1024):
                        f.write(chunk)
                        self.progress_queue.put((record, len(chunk)))
                part_path.rename(part_path.with_suffix(""))  # Remove .part suffix

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


@app.command()
def dbinit(
    db_path: str = typer.Option("/data/apk/apkindex.db", help="Path to the APK database"),
    csv_path: str = typer.Option(
        "/data/apk/apkindex.csv",
        help="Path to the CSV file containing APK records",
    ),
    force: bool = typer.Option(False, help="Force re-import of the CSV file"),
) -> None:
    """Initialize the APK database."""
    if Path(db_path).is_file() and not force:
        typer.echo("Database already exists. Use --force to overwrite.")
        raise typer.Exit(1)

    if force and Path(db_path).is_file():
        Path(db_path).unlink()

    db = AzDatabase(db_path)
    db.import_csv(csv_path)


@app.command()
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


@app.command()
def search(
    db_path: str = typer.Option("/data/apk/apkindex.db", help="Path to the APK database"),
    namelike: str = typer.Argument(..., help="Package name or part of it"),
) -> None:
    """Find APK records by package name."""
    db = AzDatabase(db_path)
    records = db.search(namelike)
    for record in records:
        rich.print(json.dumps(asdict(record), indent=2))


if __name__ == "__main__":
    app()
