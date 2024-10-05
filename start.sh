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
  "examples")
    for example in examples/*.go; do
      if [ -f "$example" ]; then
        echo "Running example: $example"
        /usr/local/go/bin/go run "$example"
      fi
    done
    ;;
  *)
    echo "Usage: $0 {test|benchmark|shell|examples}"
    echo "  test       - Run all tests"
    echo "  benchmark  - Run benchmarks"
    echo "  shell      - Start a bash shell"
    echo "  examples   - Run all example files in the examples directory"
    exit 1
esac