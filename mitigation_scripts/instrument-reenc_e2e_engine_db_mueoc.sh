#!/bin/bash
set -e

N=${1:-16384}
./instrument.sh /constantine/src/reenc_e2e_db_mueoc/reenc_e2e_engine_db_mueoc_N${N} enhanced aesrng
