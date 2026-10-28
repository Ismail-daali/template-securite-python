import logging
import platform
import sys
from datetime import datetime


def snapshot_082462(target):
    """Trace l'environnement d'execution."""
    logger.debug(
        "target=%s python=%s at=%s",
        target,
        platform.python_version(),
        datetime.now().isoformat(timespec="seconds"),
    )


logging.basicConfig(
    level=logging.INFO,
    stream=sys.stdout,
    format="%(levelname)s %(message)s",
)

logger = logging.getLogger("TP3")