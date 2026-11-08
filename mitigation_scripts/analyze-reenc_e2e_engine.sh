#!/bin/bash
set -e

N=${1:-64}

cd cipherfix
./analyze.sh /constantine/src/reenc_e2e/reenc_e2e_engine_N${N} /constantine/src/reenc_e2e/reenc_e2e_engine_N${N} "1;4;5" reenc_e2e_engine_N${N}.out