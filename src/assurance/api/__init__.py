"""HTTP API for the assurance register.

Requires the ``api`` extra (``pip install -e ".[api]"``). The core package has
no runtime dependencies; importing this module is the only place FastAPI is
needed.
"""

from .service import app, create_app, main

__all__ = ["app", "create_app", "main"]
