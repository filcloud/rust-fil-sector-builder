#!/usr/bin/env bash

set -Eeuo pipefail

if [ -z "$1" ]; then
  TAR_FILE=`mktemp`.tar.gz
else
  TAR_FILE=$1
fi

TAR_PATH=`mktemp -d`

mkdir -p $TAR_PATH
mkdir -p $TAR_PATH/include
mkdir -p $TAR_PATH/lib/pkgconfig

find . -type f -name sector_builder_ffi.h -exec cp -- "{}" $TAR_PATH/include/ \;
find . -type f -name libsector_builder_ffi.a -exec cp -- "{}" $TAR_PATH/lib/ \;
find . -type f -name sector_builder_ffi.pc -exec cp -- "{}" $TAR_PATH/lib/pkgconfig/ \;

pushd $TAR_PATH

tar -czf $TAR_FILE ./*

popd

rm -rf $TAR_PATH

echo $TAR_FILE
