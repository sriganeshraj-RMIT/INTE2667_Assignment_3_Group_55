#!/bin/bash
# R16 demo: stop the main app and show that the standby keeps answering.
# Start everything first:  docker compose -f docker-compose.yml -f docker-compose.failover.yml up --build -d
COMPOSE="docker compose -f docker-compose.yml -f docker-compose.failover.yml"
URL=http://localhost:5002/health

ask() { curl -s -m 15 -i "$URL" | grep -E "^HTTP|X-Upstream|status" | tr '\r\n' '  '; echo; }

echo "1) Normal: the main app answers"
ask
echo "2) Stopping the main app ..."
$COMPOSE stop app
start=$(date +%s)
echo "3) Asking again: the standby should answer (note the different X-Upstream address)"
for i in 1 2 3; do ask; sleep 1; done
echo "   Switched over within $(( $(date +%s) - start )) seconds"
echo "4) Starting the main app again"
$COMPOSE start app
