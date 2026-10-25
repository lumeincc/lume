#!/bin/sh
# SPDX-FileCopyrightText: 2026 LUME Inc.
# SPDX-License-Identifier: AGPL-3.0-only

set -eu

expected_fingerprint=6084F3CF814B57C1CF12EFD515CF4D18AF4F7421
key_file=$(mktemp)
curl -fsSL -o "$key_file" https://apt.llvm.org/llvm-snapshot.gpg.key
fingerprint=$(gpg --show-keys --with-colons "$key_file" | awk -F: '/^fpr/ { print $10; exit }')
if [ "$fingerprint" != "$expected_fingerprint" ]; then
    echo "apt.llvm.org key has fingerprint $fingerprint, expected $expected_fingerprint" >&2
    exit 1
fi
sudo gpg --yes --output /usr/share/keyrings/llvm.gpg --dearmor "$key_file"
echo "deb [signed-by=/usr/share/keyrings/llvm.gpg] http://apt.llvm.org/noble/ llvm-toolchain-noble-22 main" \
    | sudo tee /etc/apt/sources.list.d/llvm.list > /dev/null
sudo apt-get update
sudo apt-get install -y --no-install-recommends "$@"
