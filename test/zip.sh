#!/bin/zsh

source test.sh

echo; echo "#### lz4"
archive -z -Zl
check

echo; echo "#### xz -1"
archive -z -Zx -G1
check

echo; echo "#### xz -9"
archive -z -Zx -G9
check

echo; echo "#### bzip2 -9"
archive -z -Zb -G9
check

echo; echo "#### zstd (-3)"
archive -z
check

echo; echo "#### zstd -9"
archive -z -Zz -G9
check

echo; echo "#### zstd -11"
archive -z -Zz -G11
check

echo; echo "#### zstd -19"
archive -z -Zz -G19
check
