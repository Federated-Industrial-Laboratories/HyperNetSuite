#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Install a locked release build into a supplied prefix without elevation.
set -euo pipefail
if [[ $# != 1 ]]; then
    echo 'Usage: bash Tools/Install.sh PREFIX' >&2
    exit 2
fi
Prefix=$(realpath -m -- "$1")
cd -- "$(dirname -- "$0")/.."
cargo build --locked --release
Target=${CARGO_TARGET_DIR:-target}
install -d -m 755 -- "$Prefix/Bin" "$Prefix/Documentation/HyperNetSuite"
install -m 755 -- "$Target/release/HyperNetSuite" "$Prefix/Bin/HyperNetSuite"
install -m 644 -- Licence.txt ReadMe.md Documentation/Usage.md Documentation/Requirements.md Documentation/Pages.md Documentation/Federation.md Documentation/PrivateMail.md Documentation/TransfersAndServices.md Documentation/Adapters.md Documentation/Dependencies.md Documentation/ThirdPartyNotices.txt "$Prefix/Documentation/HyperNetSuite/"
sed 's#](Documentation/#](#g' ReadMe.md > "$Prefix/Documentation/HyperNetSuite/ReadMe.md"
printf 'Installed HyperNetSuite in %s/Bin\n' "$Prefix"
