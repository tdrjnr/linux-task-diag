#!/bin/sh
./fork 1000
nproc=`./task_diag_all A | grep 'pid.*tgid.*ppid.*comm fork$' | wc -l`
killall -9 fork
[ "$nproc" -eq 1000 ] && exit 0
echo "Unexpected number of tasks '$nproc'" 1>&2
