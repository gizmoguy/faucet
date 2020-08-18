#!/bin/bash

SCRIPT_PATH=$(readlink -f "$0")
SCRIPT_DIR=$(dirname "${SCRIPT_PATH}")
BASE_DIR=$(readlink -f "${SCRIPT_DIR}/..")

sharded_tests=()

function shard_tests {
  test_files=(
    "${BASE_DIR}/tests/integration/mininet_tests.py"
    "${BASE_DIR}/tests/integration/mininet_multidp_tests.py"
    "${BASE_DIR}/clib/clib_mininet_tests.py"
  )

  all_tests=$(
    grep -E -o "^class (Faucet[a-zA-Z0-9]+Test)" "${test_files[@]}" | cut -f2 -d" " | sort
  )

  total_shards=$1
  i=0
  for test in ${all_tests} ; do
    sharded_tests[$i]="${sharded_tests[$i]} ${test}"
    i=$(( (i + 1) % total_shards ))
  done
}

shard_tests "$1"

echo "${sharded_tests[$2]}"
