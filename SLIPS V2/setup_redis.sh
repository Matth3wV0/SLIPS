#!/bin/bash
# Script to reset Redis server with proper configuration

echo "Stopping any existing Redis server..."
redis-cli shutdown || true
sleep 1

echo "Starting Redis server with persistence disabled..."
redis-server --daemonize yes --save "" --stop-writes-on-bgsave-error no

echo "Redis server restarted with persistence disabled."
echo "Now you can run your SLIPS application."
