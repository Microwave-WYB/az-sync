from az_sync.cli import root
from loguru import logger


def main() -> None:
    try:
        root()
    except Exception as e:
        logger.exception(e)
        raise


__all__ = []
