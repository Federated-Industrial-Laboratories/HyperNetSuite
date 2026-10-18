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
Documents="$Prefix/Documentation/HyperNetSuite"
install -d -m 755 -- "$Prefix/Bin" "$Documents/Documentation"
install -m 755 -- "$Target/release/HyperNetSuite" "$Prefix/Bin/HyperNetSuite"
install -m 644 -- Licence.txt "$Documents/"
install -m 644 -- Documentation/*.md Documentation/*.json Documentation/ThirdPartyNotices.txt "$Documents/Documentation/"
install -d -m 755 -- "$Prefix/Examples"
install -m 644 -- Examples/*.py Examples/*.png Examples/*.svg Examples/*.md Examples/*.txt "$Prefix/Examples/"
sed 's#](Examples/#](../../Examples/#g' ReadMe.md > "$Documents/ReadMe.md"
for Manual in Documentation/*.md; do
    sed 's#](../Examples/#](../../../Examples/#g' "$Manual" > "$Documents/Documentation/${Manual##*/}"
done
sed -e 's#](../Documentation/#](../Documentation/HyperNetSuite/Documentation/#g' \
    -e 's#](../ReadMe.md)#](../Documentation/HyperNetSuite/ReadMe.md)#g' \
    Examples/ReadMe.md > "$Prefix/Examples/ReadMe.md"
printf 'Installed HyperNetSuite in %s/Bin\n' "$Prefix"
