"""FortifyRoot SDK version.

The package version is defined in ``pyproject.toml``. Installed wheels and
editable installs expose that value through distribution metadata, so this file
does not duplicate the literal version.
"""

import logging
from importlib.metadata import PackageNotFoundError, version


logger = logging.getLogger(__name__)


try:
    __version__ = version("fortifyroot-sdk")
except PackageNotFoundError:
    __version__ = "0+unknown"
    logger.warning(
        "fortifyroot-sdk package metadata was not found; using version %s",
        __version__,
    )
