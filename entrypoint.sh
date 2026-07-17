#!/usr/bin/env bash

set -e

BINARY=/aby/build/bin/aby_interpreter
CIRCUIT_DIR=/circuit
SHARE_ASSIGNMENT_FILE=/share_assignment.txt

# server
"$BINARY" -m mpc -f "$CIRCUIT_DIR" -s "$SHARE_ASSIGNMENT_FILE" -r 0 &

sleep 1

# client
"$BINARY" -m mpc -f "$CIRCUIT_DIR" -s "$SHARE_ASSIGNMENT_FILE" -r 1 &

wait
