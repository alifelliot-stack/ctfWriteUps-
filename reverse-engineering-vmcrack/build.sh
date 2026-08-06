#!/bin/sh
# Builds ./vmcrack from vm.c + bytecode.h (already generated and committed --
# rerun gen_bytecode.py yourself only if you want to mint a new flag).
set -e
cd "$(dirname "$0")"
gcc -O0 -o vmcrack vm.c
echo "Built ./vmcrack"
