#!/bin/sh
set -e

ARGS=""

# Process arguments
if [ "$2" = "--strict" ]; then
  ARGS="$ARGS --strict"
fi

CONFIG_PATH="critical_dependencies.yaml"
if [ "$3" = "--config" ] && [ -n "$4" ]; then
  CONFIG_PATH="$4"
fi

# Run the scanner with appropriate arguments
gh-action-security-scanner "$1" $ARGS --config "$CONFIG_PATH"