#!/bin/sh
# SPDX-FileCopyrightText: 2026 LUME Inc.
# SPDX-License-Identifier: AGPL-3.0-only

set -eu

expected_fingerprint=6084F3CF814B57C1CF12EFD515CF4D18AF4F7421
work=$(mktemp -d)
export GNUPGHOME="$work/gnupg"
mkdir -m 700 "$GNUPGHOME"

curl -fsSL -o "$work/llvm.asc" https://apt.llvm.org/llvm-snapshot.gpg.key
fingerprints=$(gpg --show-keys --with-colons "$work/llvm.asc" | awk -F: '/^pub/ { primary = 1; next } /^fpr/ && primary { print $10; primary = 0 }')
if [ "$fingerprints" != "$expected_fingerprint" ]; then
    echo "apt.llvm.org served keys [$fingerprints], expected exactly $expected_fingerprint" >&2
    exit 1
fi
gpg --quiet --import "$work/llvm.asc"
gpg --export "$expected_fingerprint" > "$work/llvm.gpg"
sudo install -m 644 "$work/llvm.gpg" /usr/share/keyrings/llvm.gpg

echo "deb [signed-by=/usr/share/keyrings/llvm.gpg] http://apt.llvm.org/noble/ llvm-toolchain-noble-22 main" \
    | sudo tee /etc/apt/sources.list.d/llvm.list > /dev/null
sudo apt-get update
sudo apt-get install -y --no-install-recommends "$@"
