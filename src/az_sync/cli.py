import json
import sys
from pathlib import Path
from collections.abc import Iterator

import typer

from az_sync.core import AzConfig, AzDatabase, AzDownload, AzWorkspace

root = typer.Typer(
    help="Sync APK files from Androzoo.",
)


def ensure_workspace() -> AzWorkspace:
    if (ws := AzWorkspace.search_workspace(Path.cwd())) is None:
        typer.echo("No workspace found, run 'azsync init' first")
        raise typer.Exit(1)
    return ws


@root.command()
def init(
    apikey: str = typer.Option(default="", help="Androzoo API key"),
    workspace_path: Path = typer.Option(".", "-d", help="Workspace path"),
    max_workers: int = typer.Option(40, help="Max workers for download"),
    skip: list[str] | None = typer.Option(
        None, help="Skip steps: [fetch-apk|fetch-metadata|import-metadata|import-apk-list] ..."
    ),
) -> None:
    """Initialize azsync workspace"""
    try:
        user_option = (
            input(
                "The init process may take 30 minutes to more than 1 hour, depending on the Internet and disk performance.\n"
                "This is a one time process.\n"
                "Are you sure you want to continue? (y/N): "
            )
            or "N"
        )
        if user_option.lower() != "y":
            typer.echo("Init process aborted.")
            raise typer.Exit(1)
        ws = AzWorkspace(workspace_path)
        apikey = ws.config.apikey or input("Enter your AndroZoo API key: ")
        ws.write_config(AzConfig(apikey=apikey, max_workers=max_workers))
        assert ws.config
        skip = skip or []
        if "fetch-apk-list" not in skip:
            ws.fetch_apk_list()
        else:
            typer.echo("Skipping APK list fetch")
        if "fetch-metadata" not in skip:
            ws.fetch_metadata(ws.config.apikey)
        else:
            typer.echo("Skipping metadata fetch")
        db = AzDatabase(ws.db_path)
        cursor = db.conn.cursor()
        cursor.execute("PRAGMA journal_mode = OFF")
        cursor.execute("PRAGMA synchronous = 0")
        cursor.execute("PRAGMA cache_size = 100000")
        cursor.execute("PRAGMA locking_mode = EXCLUSIVE")
        cursor.execute("PRAGMA temp_store = MEMORY")
        if "import-metadata" not in skip:
            db.import_metadata(ws.metadata_path)
        else:
            typer.echo("Skipping metadata import")
        if "import-apk-list" not in skip:
            db.import_apk_list(ws.apk_list_path)
        else:
            typer.echo("Skipping APK list import")
        typer.echo("Initialization complete!")
    except KeyboardInterrupt as e:
        typer.echo(f"KeyboardInterrupt occurred during initialization: {e}")
        raise typer.Exit(1)


@root.command()
def info(
    queries: list[str] | None = typer.Argument(
        None, help="SHA256 | Package name (support wildcard characteres % and _)"
    ),
    indent: int | None = typer.Option(None, help="JSON indentation level"),
) -> None:
    """Find APK records by package name or sha256"""
    ws = ensure_workspace()
    db = AzDatabase(ws.db_path)
    qiter: Iterator[str] = iter(queries) if queries else sys.stdin
    for query in qiter:
        for result in db.search(query.strip()):
            typer.echo(result.model_dump_json(indent=indent))


@root.command("list")
def list_(
    offset: int = typer.Option(0, "-o", help="Offset of lines to display"),
    limit: int = typer.Option(50, "-n", help="Number of lines to display"),
    indent: int | None = typer.Option(None, help="JSON indentation level"),
):
    """Display the first few lines of the APK list"""
    ws = ensure_workspace()
    db = AzDatabase(ws.db_path)
    for apk in db.list_(offset=offset, limit=limit):
        typer.echo(apk.model_dump_json(indent=indent))


@root.command()
def metadata(
    pkg_name: str | None = typer.Option(None, "-n", "--pkgname", help="Package name"),
    vercode: int | None = typer.Option(None, "-v", "--vercode", help="Version code"),
    contains: str | None = typer.Option(
        None, "-c", "--contains", help="Filter by substring in metadata jsonl"
    ),
    indent: int | None = typer.Option(None, help="JSON indentation level"),
):
    """Display the metadata of the APKs"""
    if not any([pkg_name, vercode, contains]):
        typer.echo(
            "Please provide at least one of the following options: --pkgname, --vercode, --contains"
        )
        raise typer.Exit(1)
    ws = ensure_workspace()
    db = AzDatabase(ws.db_path)
    metadata_list = db.metadata(pkg_name=pkg_name, vercode=vercode, contains=contains)
    for metadata in metadata_list:
        typer.echo(json.dumps(json.loads(metadata.data), indent=indent))


@root.command()
def download(
    sha256s: list[str] | None = typer.Argument(
        None, help="SHA256s of APKs to download. If not provided, read from stdin"
    ),
    output_dir: Path = typer.Option("downloads", "-d", help="Output directory"),
    max_workers: int | None = typer.Option(
        None, "-w", help="Overwrite max_workers in the config file and download"
    ),
):
    """Download APKs by SHA256"""
    ws = ensure_workspace()
    sha256iter: Iterator[str] = iter(sha256s) if sha256s else sys.stdin
    if max_workers:
        downloader = AzDownload(ws.config.apikey, output_dir, max_workers)
    else:
        downloader = AzDownload(ws.config.apikey, output_dir, ws.config.max_workers)
    downloader.download_all(sha256iter)
