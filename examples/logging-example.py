"""Deliberately sloppy logging — exercises LOG101–LOG105.

Used to dogfood the Python logging rules on a real PR.
Do not copy this style.
"""

import logging

logger = logging.getLogger(__name__)


def report_user(name: str) -> None:
    """Report a login, formatting the message eagerly."""
    logging.info("User %s logged in" % name)


def report_count(count: int) -> None:
    """Report a count, formatting the message eagerly."""
    logger.info(f"Processed {count} items")


def report_failure() -> None:
    """Log an exception with no handler in sight."""
    logging.exception("Something failed")


def report_status(status: str) -> None:
    """Report a status, formatting the message eagerly."""
    logging.info("Status: {}".format(status))


def warn_user() -> None:
    """Warn the user, the deprecated way."""
    logging.warn("Heads up")


def report_user_lazily(name: str) -> None:
    """Report a login, letting logging format it lazily."""
    logger.info("User %s logged in", name)


def handle_error() -> None:
    """Log an exception inside a handler, the right way."""
    try:
        risky()
    except ValueError:
        logger.exception("Something failed")
