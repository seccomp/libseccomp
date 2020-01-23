#!/bin/bash

SYSCALLS_CSV=$1
SYSCALLS_PERF_TEMPLATE=$2

cat $SYSCALLS_CSV | grep -v '^#' | nl -ba -s, -v0 | \
    sed -e 's/^[[:space:]]\+\([[:digit:]]\+\),\(.*\)$/\2,\1/' \
        -e ':repeat; {s|\([^,]\+\)\(.*\)[^_]PNR|\1\2 __PNR_\1|g;}; t repeat' \
         > syscalls.csv.tmp

sed -e '/@@SYSCALLS_TABLE@@/r syscalls.csv.tmp' \
    -e '/@@SYSCALLS_TABLE@@/d' \
    $SYSCALLS_PERF_TEMPLATE > syscalls.perf.tmp

rm syscalls.csv.tmp
mv -f syscalls.perf.tmp syscalls.perf
