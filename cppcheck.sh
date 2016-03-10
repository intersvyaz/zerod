#!/bin/sh

cppcheck -q \
    --enable=all \
    --inconclusive \
    --library=/usr/share/cppcheck/cfg/std.cfg \
    --library=/usr/share/cppcheck/cfg/posix.cfg \
    --library=/usr/share/cppcheck/cfg/gnu.cfg \
    --std=c11 \
    --platform=unix64 \
    -Ibuild \
    ./src
