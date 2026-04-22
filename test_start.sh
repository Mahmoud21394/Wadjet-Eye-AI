#!/bin/bash
cd /home/user/webapp/backend
export JWT_SECRET=test_secret_key_for_dev_minimum_32_chars
export NODE_ENV=development
node server.js &
SERVER_PID=$!
sleep 6
if curl -s http://localhost:4000/api/ping > /tmp/ping_out.txt 2>&1; then
  echo "SERVER OK: $(cat /tmp/ping_out.txt)"
else
  echo "SERVER FAILED after 6s"
  # Show last 30 lines of output
fi
# Try health
curl -s http://localhost:4000/api/health 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print('Health:', d['status'])" 2>/dev/null || echo "Health endpoint unreachable"
echo "Done. Killing server."
kill $SERVER_PID 2>/dev/null
