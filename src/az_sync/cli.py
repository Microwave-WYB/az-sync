import json
import sys
from pathlib import Path
from collections.abc import Iterable

import typer

from az_sync.core import AzConfig, AzDatabase, AzDownload, AzWorkspace

root = typer.Typer(
    help="Sync APK files from Androzoo.",
)
page_app = typer.Typer(
    help="Get a page of APK info or metadata",
)
root.add_typer(page_app, name="page")
iter_app = typer.Typer(
    help="Iterate over APK info or metadata",
)
root.add_typer(iter_app, name="iter")
search_app = typer.Typer(
    help="Search for APK info or metadata",
)
root.add_typer(search_app, name="search")


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


@search_app.command("apk")
def search_apk(
    pkg_names: list[str] | None = typer.Argument(None, help="Package name"),
    wildcard: bool = typer.Option(
        False, "--wildcard", help="Enable wildcard search. Disabled by default"
    ),
    indent: int | None = typer.Option(None, help="JSON indentation level"),
) -> None:
    """Find APK records by sha256, package name, or version code"""
    ws = ensure_workspace()
    db = AzDatabase(ws.db_path)
    pkg_name_iter: Iterable[str] = pkg_names if pkg_names is not None else sys.stdin
    for name in pkg_name_iter:
        results = db.search_apk(name.strip(), wildcard)
        for result in results:
            typer.echo(result.model_dump_json(indent=indent))


@search_app.command("metadata")
def search_metadata(
    pkg_name: str | None = typer.Option(None, "-p", "--pkgname", help="Package name"),
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
    results = db.search_metadata(pkg_name=pkg_name, vercode=vercode, contains=contains)
    for result in results:
        typer.echo(json.dumps(json.loads(result.data), indent=indent))


@page_app.command("apk")
def page_apk(
    offset: int = typer.Option(0, "-o", help="Offset of lines to display", min=0),
    limit: int = typer.Option(50, "-n", help="Number of lines to display", min=1, max=500),
    indent: int | None = typer.Option(None, help="JSON indentation level"),
):
    """Display the first few lines of the APK list"""
    ws = ensure_workspace()
    db = AzDatabase(ws.db_path)
    for apk in db.list_apks(offset=offset, limit=limit):
        typer.echo(apk.model_dump_json(indent=indent))


@page_app.command("metadata")
def page_metadata(
    offset: int = typer.Option(0, "-o", help="Offset of lines to display", min=0),
    limit: int = typer.Option(50, "-n", help="Number of lines to display", min=1, max=500),
    indent: int | None = typer.Option(None, help="JSON indentation level"),
):
    """Display the first few lines of the APK metadata"""
    ws = ensure_workspace()
    db = AzDatabase(ws.db_path)
    for m in db.list_metadata(offset=offset, limit=limit):
        typer.echo(json.dumps(json.loads(m.data), indent=indent))


@iter_app.command("apk")
def iter_apk(
    indent: int = typer.Option(None, help="JSON indentation level"),
):
    """Iterate over the APKs"""
    ws = ensure_workspace()
    db = AzDatabase(ws.db_path)
    for r in db.iter_records():
        typer.echo(r.model_dump_json(indent=indent))


@iter_app.command("metadata")
def iter_metadata(
    indent: int = typer.Option(None, help="JSON indentation level"),
):
    """Iterate over the APK metadata"""
    ws = ensure_workspace()
    db = AzDatabase(ws.db_path)
    for m in db.iter_metadata():
        typer.echo(json.dumps(json.loads(m.data), indent=indent))


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
    sha256iter: Iterable[str] = sha256s if sha256s else sys.stdin
    if max_workers:
        downloader = AzDownload(ws.config.apikey, output_dir, max_workers)
    else:
        downloader = AzDownload(ws.config.apikey, output_dir, ws.config.max_workers)
    downloader.download_all(sha256iter)
