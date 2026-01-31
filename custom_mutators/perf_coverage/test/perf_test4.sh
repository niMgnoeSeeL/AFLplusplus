#!/bin/bash
# Test pipe-based perf with output capture
gcc -O0 -o /tmp/spin /tmp/spin.c 2>/dev/null

/tmp/spin &
SPIN_PID=$!
echo "Spin PID: $SPIN_PID"

# Test the pipe approach with output to file
(perf record --no-buffering -F 1000 -p $SPIN_PID -o - 2>/dev/null | perf script -i - 2>/dev/null) > /tmp/pipe_output.txt &
PIPE_PID=$!

sleep 2
kill $PIPE_PID 2>/dev/null
wait

echo "=== Pipe output ==="
head -30 /tmp/pipe_output.txt
echo "=== Line count ==="
wc -l /tmp/pipe_output.txt
