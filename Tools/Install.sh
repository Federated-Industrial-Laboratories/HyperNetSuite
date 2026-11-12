#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Install a locked release build into a supplied prefix without elevation.
set -euo pipefail
if [[ $# == 0 ]]; then
    package_root=$(cd -- "$(dirname -- "$0")/.." && pwd -P)
    if [[ ! -d "$package_root/Packages/Core" || ! -d "$package_root/Packages/Suite" ]]; then
        echo 'This packaged installer needs the complete adjacent Packages/Core and Packages/Suite sets.' >&2
        exit 2
    fi
    exec /usr/bin/python3 -I -S -c 'import sys,runpy; sys.path.insert(0,sys.argv.pop(1)); sys.argv=sys.argv[1:]; runpy.run_path(sys.argv[0],run_name="__main__")' \
        "$package_root/Tools" "$package_root/Tools/Bundle.py" Bootstrap --release-directory "$package_root/Packages"
fi
if [[ $# != 1 ]]; then
    echo 'Usage: bash Tools/Install.sh [SOURCE_BUILD_PREFIX]' >&2
    exit 2
fi
Prefix=$(realpath -m -- "$1")
cd -- "$(dirname -- "$0")/.."
cargo build --locked --release
Target=${CARGO_TARGET_DIR:-target}
Documents="$Prefix/Documentation/HyperNetSuite"
install -d -m 755 -- "$Prefix/Bin" "$Documents/Documentation" "$Documents/.github/assets"
install -m 755 -- "$Target/release/HyperNetSuite" "$Prefix/Bin/HyperNetSuite"
install -m 644 -- Licence.txt "$Documents/"
install -m 644 -- Documentation/*.md Documentation/*.json Documentation/*.txt "$Documents/Documentation/"
install -m 644 -- .github/assets/header.svg "$Documents/.github/assets/"
install -d -m 755 -- "$Prefix/Examples"
install -m 644 -- Examples/*.py Examples/*.png Examples/*.svg Examples/*.md Examples/*.txt "$Prefix/Examples/"
sed 's#](Examples/#](../../Examples/#g' ReadMe.md > "$Documents/ReadMe.md"
for Manual in Documentation/*.md; do
    sed -e 's#](../Examples/#](../../../Examples/#g' -e 's#](../SDK/#](../../../SDK/#g' "$Manual" > "$Documents/Documentation/${Manual##*/}"
done
sed -e 's#](../Documentation/#](../Documentation/HyperNetSuite/Documentation/#g' \
    -e 's#](../ReadMe.md)#](../Documentation/HyperNetSuite/ReadMe.md)#g' \
    Examples/ReadMe.md > "$Prefix/Examples/ReadMe.md"

install -d -m 755 -- "$Prefix/SDK/hypernet_streams" "$Prefix/Examples/ApplicationStreams"
install -m 644 -- SDK/pyproject.toml SDK/Licence.txt "$Prefix/SDK/"
sed 's#](../Documentation/#](../Documentation/HyperNetSuite/Documentation/#g' SDK/README.md > "$Prefix/SDK/README.md"
install -m 644 -- SDK/hypernet_streams/__init__.py SDK/hypernet_streams/context.py "$Prefix/SDK/hypernet_streams/"
install -m 644 -- Examples/ApplicationStreams/stream_service.py Examples/ApplicationStreams/authority_service.py "$Prefix/Examples/ApplicationStreams/"
python3 -m pip wheel --no-deps --no-build-isolation --wheel-dir "$Prefix/SDK" ./SDK
printf 'Installed HyperNetSuite in %s/Bin\n' "$Prefix"
