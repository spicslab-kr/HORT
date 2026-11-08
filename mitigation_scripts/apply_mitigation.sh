#!/bin/bash
set -e

N=${1:-64}
echo "[+] Applying Mitigations for N=${N}"

chmod +x *

./all-in-one-reenc_e2e_engine_lwe.sh ${N}

./all-in-one-reenc_e2e_engine.sh ${N}

./all-in-one-reenc_e2e_engine_slot.sh ${N}

