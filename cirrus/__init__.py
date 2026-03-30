"""CIRRUS — Cloud Incident Response & Reconnaissance Utility Suite."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("cirrus")
except PackageNotFoundError:
    __version__ = "0.0.0.dev"

__author__ = "CIRRUS Contributors"
