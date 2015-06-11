#!/bin/sh
./fork 1000 10
nproc=`./task_diag_all A | grep 'pid.*tgid.*ppid.*comm fork$' | wc -l`
killall -9 fork
[ "$nproc" -eq 10000 ] && exit 0
echo "Unexpected number of tasks '$nproc'" 1>&2
