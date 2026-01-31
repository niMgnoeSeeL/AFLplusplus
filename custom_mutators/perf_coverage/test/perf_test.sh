#!/bin/bash
sleep 10 &
SLEEP_PID=$!
echo "Sleep PID: $SLEEP_PID"

perf record -F 1000 -p $SLEEP_PID -o /tmp/test7.perf &
PERF_PID=$!

sleep 3
kill $PERF_PID 2>/dev/null
kill $SLEEP_PID 2>/dev/null
wait

echo "=== Perf file ==="
ls -la /tmp/test7.perf

echo "=== Perf script output ==="
perf script -i /tmp/test7.perf 2>&1 | head -20
