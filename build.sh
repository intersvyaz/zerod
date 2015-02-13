#!/usr/bin/env sh

rm -rf ./build
mkdir build
cd build
cmake .. && make
