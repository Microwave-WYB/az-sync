import sys
from az_sync.cli import root
from az_sync.core import AzDownload, AzDatabase
from loguru import logger

logger.remove()  # Do not print to console
logger.add(
    "logs/sync_{time:%Y-%m-%d_%H-%M-%S}.log",
    rotation="50 MB",
)
logger.add(
    "logs/sync_latest.log",
    rotation="50 MB",
)
logger.add(
    "logs/error.log",
    rotation="50 MB",
    level="ERROR",
    backtrace=True,
    diagnose=True,
)


def main() -> None:
    """Main function to run the az_sync CLI."""
    logger.info(f"Command: {' '.join(sys.argv)}")
    try:
        root()
    except Exception as e:
        logger.exception(e)
        raise


__all__ = []
