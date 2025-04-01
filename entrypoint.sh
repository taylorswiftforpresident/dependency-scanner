#!/bin/sh
set -e

ARGS=""

# Process arguments
if [ "$2" = "--strict" ]; then
  ARGS="$ARGS --strict"
fi

if [ "$3" = "--config" ] && [ -n "$4" ]; then
  # Copy the config file to the expected location
  mkdir -p $(dirname critical_dependencies.yaml)
  cp "$4" critical_dependencies.yaml
fi

# Run the scanner
gh-action-security-scanner $ARGS "$1"