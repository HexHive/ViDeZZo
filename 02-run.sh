#!/bin/bash -x

WORKDIR=$1
TARGET=$2
pushd $WORKDIR
for ROUND in $(seq 0 9); do
    cpulimit -l 100 -- $TARGET -max_total_time=86400 >$TARGET-$ROUND.log 2>&1 &
    sleep 1
done
popd
