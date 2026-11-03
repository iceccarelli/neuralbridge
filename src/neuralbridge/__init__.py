"""
NeuralBridge — the platform behind Industrial Autonomous Assurance.

``assurance`` (src/assurance) is the product: hash-chained evidence and change
assurance for machines whose software can affect safety. This package is the
integration platform it grew out of (adapters, MCP layer); its adapters are
experimental unless the README's status table says Supported.

Copyright (c) 2026 Vincenzo Ceccarelli Grimaldi. All rights reserved.
Proprietary: see the LICENSE file. No licence is granted except by written agreement.
"""

__version__ = "0.1.1"
__author__ = "Vincenzo Ceccarelli Grimaldi"
__license__ = "Proprietary"

from neuralbridge.config import Settings  # noqa: F401
