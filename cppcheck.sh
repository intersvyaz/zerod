#!/usr/bin/env sh

cppcheck -q \
    --enable=all \
    --inconclusive \
    --library=/usr/share/cppcheck/cfg/std.cfg \
    --library=/usr/share/cppcheck/cfg/posix.cfg \
    --library=cppcheck.xml \
    --std=c11 \
    --platform=unix64 \
    -Ibuild \
    ./src