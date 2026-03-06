#!/usr/bin/env bash

./build/tcp &
tcp_pid=$!

echo "Run perf stat"
perf stat -d -o stat.txt -p $tcp_pid -- make test

echo "Run perf record"
perf record -F 99 -p $tcp_pid -g -- make test
echo "Kill tcp process"
kill $tcp_pid

echo "Generate flamegraph"
perf script > out.perf
../flamegraph/stackcollapse-perf.pl out.perf > out.folded
../flamegraph/flamegraph.pl out.folded > tcp.svg

echo "Delete unnecessary files"
rm out.perf out.folded
