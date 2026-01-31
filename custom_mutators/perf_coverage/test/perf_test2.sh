#!/bin/bash
# CPU-bound test
cat > /tmp/spin.c << 'EOF'
int main() {
    volatile long x = 0;
    for(long i = 0; i < 100000000; i++) x += i;
    return 0;
}
EOF

gcc -O0 -o /tmp/spin /tmp/spin.c

/tmp/spin &
SPIN_PID=$!
echo "Spin PID: $SPIN_PID"

perf record -F 1000 -p $SPIN_PID -o /tmp/test8.perf &
PERF_PID=$!

sleep 2
kill $PERF_PID 2>/dev/null
wait

echo "=== Perf file ==="
ls -la /tmp/test8.perf

echo "=== Perf script output ==="
perf script -i /tmp/test8.perf 2>&1 | head -30
