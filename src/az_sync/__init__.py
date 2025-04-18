import typer

from az_sync.core import sync


def main() -> None:
    """Main function to run the az_sync CLI."""
    typer.run(sync)
