#!/bin/bash
set -e

N=${1:-16384}
echo "[+] Applying DB mitigations for CKKS N=${N}"

chmod +x *

./all-in-one-reenc_e2e_engine_lwe.sh ${LWE_BUILD_N:-64}
./all-in-one-reenc_e2e_engine_db.sh ${N}
./all-in-one-reenc_e2e_engine_slot_db.sh ${N}
