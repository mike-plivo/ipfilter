#!/bin/bash
redis-server --daemonize yes
sleep 1
case "$1" in
  "test")
    /usr/local/go/bin/go test ./...
    ;;
  "benchmark"|"bench")
    /usr/local/go/bin/go test -bench=. ./...
    ;;
  "shell"|"sh"|"bash")
    /bin/bash
    ;;
  *)
    echo "Usage: $0 {test|benchmark|shell}"
    exit 1
esac