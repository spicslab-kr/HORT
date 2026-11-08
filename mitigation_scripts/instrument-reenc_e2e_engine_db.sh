#!/bin/bash
set -e

N=${1:-16384}
./instrument.sh /constantine/src/reenc_e2e_db/reenc_e2e_engine_db_N${N} enhanced aesrng
