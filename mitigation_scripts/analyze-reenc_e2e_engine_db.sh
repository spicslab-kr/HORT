#!/bin/bash
set -e

N=${1:-16384}
./analyze.sh /constantine/src/reenc_e2e_db/reenc_e2e_engine_db_N${N} /constantine/src/reenc_e2e_db/reenc_e2e_engine_db_N${N} "1;4;5" reenc_e2e_engine_db_N${N}.out
