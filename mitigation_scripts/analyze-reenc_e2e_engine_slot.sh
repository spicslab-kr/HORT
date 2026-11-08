#!/bin/bash
set -e

N=${1:-64}

cd cipherfix
./analyze.sh /constantine/src/reenc_e2e_slot/reenc_e2e_engine_slot_N${N} /constantine/src/reenc_e2e_slot/reenc_e2e_engine_slot_N${N} "1;4;5" reenc_e2e_engine_slot_N${N}.out