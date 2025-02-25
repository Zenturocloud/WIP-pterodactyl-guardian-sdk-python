"""
Pterodactyl Guardian SDK for Python.

A comprehensive Python SDK for implementing abuse detection and 
security monitoring for Pterodactyl Panel via the Pterodactyl API.
"""

from .client import PterodactylGuardian
from .version import __version__

__all__ = ["PterodactylGuardian", "__version__"]
