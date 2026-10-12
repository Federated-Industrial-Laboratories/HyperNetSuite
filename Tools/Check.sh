#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Check the independent client; failures return a nonzero status.
set -euo pipefail
cd -- "$(dirname -- "$0")/.."
# Retain interrupted fixtures on persistent private storage across host restarts.
export TMPDIR=${HYPERNET_TEST_DIRECTORY:-${XDG_STATE_HOME:-$HOME/.local/state}/HyperNetSuite/Tests}
mkdir -p -m 0700 "$TMPDIR"
python3 - "$TMPDIR" <<'PYTHON'
import os
from pathlib import Path
import stat
import sys
path = Path(sys.argv[1])
metadata = path.lstat()
if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
    raise SystemExit('Test directory must be private and owned by the current user')
PYTHON
cargo fmt --all --check
cargo clippy --release --locked --all-targets -- -D warnings
cargo test --release --locked
