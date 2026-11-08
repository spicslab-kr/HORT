#!/bin/bash
set -e

RING_N=${1:-65536}
if [ "${RING_N}" = "64" ]; then
  RING_N=65536
fi
LWE_N=${LWE_BUILD_N:-64}
echo "[+] Applying MUEOC mitigations for CKKS N=${RING_N}, LWE build N=${LWE_N}"

chmod +x *

./all-in-one-reenc_e2e_engine_lwe.sh ${LWE_N}

./all-in-one-reenc_e2e_engine_mueoc.sh ${RING_N}

./all-in-one-reenc_e2e_engine_slot_mueoc.sh ${RING_N}
