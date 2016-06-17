#!/bin/sh

set -e

test_dir=`mktemp -d /tmp/lookup_test.XXXXXX`
mount -t tmpfs lookup_at_root $test_dir

ret=0
./lookup_at_root $test_dir || ret=$?

umount $test_dir
rmdir $test_dir

exit $ret
