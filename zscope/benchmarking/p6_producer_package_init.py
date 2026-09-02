"""Minimal package initializer for the physical P6 host-producer sandbox.

The normal :mod:`zscope.benchmarking` package exports post-score and experiment
APIs.  Importing those exports would require copying the scorer into the cold
producer tree.  The deterministic sandbox materializer installs this exact
blob as ``zscope/benchmarking/__init__.py`` instead.
"""

__all__: list[str] = []
