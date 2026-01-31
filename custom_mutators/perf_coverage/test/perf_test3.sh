#!/bin/bash
# Test pipe-based perf (like our mutator uses)
gcc -O0 -o /tmp/spin /tmp/spin.c 2>/dev/null

/tmp/spin &
SPIN_PID=$!
echo "Spin PID: $SPIN_PID"

# Test the pipe approach
(perf record --no-buffering -F 1000 -p $SPIN_PID -o - 2>/dev/null | perf script -i - 2>/dev/null) &
PIPE_PID=$!

sleep 2
kill $PIPE_PID 2>/dev/null
wait

echo "Done"
