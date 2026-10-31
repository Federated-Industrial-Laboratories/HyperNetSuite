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
if not path.is_absolute() or path.resolve() != path:
    raise SystemExit('Test directory must have an absolute canonical path')
for ancestor in path.parents:
    metadata = ancestor.lstat()
    protected = not metadata.st_mode & 0o022 or metadata.st_uid == 0 and metadata.st_mode & stat.S_ISVTX
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid not in (0, os.geteuid()) or not protected:
        raise SystemExit('Test directory ancestors must prevent replacement by other users')
# Reserve the fixture directory and longest socket name within Linux sun_path.
if len(os.fsencode(path / ('I' + '0' * 16) / 'UnavailableAuthority.sock')) >= 108:
    raise SystemExit('Test directory is too long for Unix sockets; set HYPERNET_TEST_DIRECTORY to a shorter private path')
PYTHON
# Bound concurrent clock-sensitive fixtures unless the caller selects a limit.
export RUST_TEST_THREADS="${RUST_TEST_THREADS:-4}"
cargo fmt --all --check
# Include files retain module scope and are not discovered by cargo fmt.
shopt -s globstar
rustfmt --edition 2024 --check Tests/**/*.rs
cargo clippy --release --locked --all-targets -- -D warnings
cargo test --release --locked
