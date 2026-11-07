#!/usr/bin/env bash
# Run the complete buyer path against the real API on loopback with ZERO real credentials.
# "local rehearsal, not a hosted staging proof": see scripts/rehearse_local.py for exactly what
# it does and does not establish. For a hosted host use scripts/staging_rehearsal.py.
#
#   scripts/rehearse-local.sh [--record-dir DIR] [--keep] [--with-site]
#
# Exit 0 every step passed | 1 a step failed | 2 could not run.
set -euo pipefail
cd "$(dirname "$0")/.."
exec "${PYTHON:-python}" scripts/rehearse_local.py "$@"
