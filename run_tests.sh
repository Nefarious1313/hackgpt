#!/usr/bin/env bash
# Run the HackGPT test suite from the project root.
set -euo pipefail
cd "$(dirname "$0")"
exec python3 -m unittest discover -s tests -t . "$@"
