#!/usr/bin/env bash
# Reproducible build of KLONER's own trivial fixture apps (unsigned).
# Requires: JDK 17+, Android build-tools 36.0.0, platforms/android-36.
# See scripts/build_fixture_apks.py for the recipe; outputs go to src/kloner/selftest/fixtures/.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
py="${PYTHON:-python3}"
command -v "$py" >/dev/null 2>&1 || py=python
exec "$py" "$here/build_fixture_apks.py" "$@"
