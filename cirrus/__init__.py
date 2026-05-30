# Copyright (c) 2026 FLINTEK LLC
# Licensed under the Apache License, Version 2.0.
# See LICENSE in the project root for license information.

"""CIRRUS — Cloud Incident Response & Reconnaissance Utility Suite."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("cirrus")
except PackageNotFoundError:
    __version__ = "0.0.0.dev"

__author__ = "FLINTEK LLC"
