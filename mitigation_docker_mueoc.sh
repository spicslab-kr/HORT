#!/bin/bash
set -e

N=${1:-65536}
if [ "${N}" = "64" ]; then
  N=65536
fi
CIPHERFIX_CONTAINER=${CIPHERFIX_CONTAINER:-cipherfix}
echo "[+] Applying MUEOC mitigations for N=${N}"

docker exec "${CIPHERFIX_CONTAINER}" /bin/bash -lc 'mkdir -p /constantine/src/reenc'
docker cp ./src_engine/reenc_e2e_engine_lwe.c "${CIPHERFIX_CONTAINER}":/constantine/src/reenc/
docker cp ./src_engine/reenc_e2e_engine_slot_mueoc.c "${CIPHERFIX_CONTAINER}":/constantine/src/reenc/
docker cp ./src_engine/reenc_e2e_engine_mueoc.c "${CIPHERFIX_CONTAINER}":/constantine/src/reenc/

docker cp ./mitigation_scripts/all-in-one-reenc_e2e_engine_mueoc.sh "${CIPHERFIX_CONTAINER}":/cipherfix/
docker cp ./mitigation_scripts/all-in-one-reenc_e2e_engine_lwe.sh "${CIPHERFIX_CONTAINER}":/cipherfix/
docker cp ./mitigation_scripts/all-in-one-reenc_e2e_engine_slot_mueoc.sh "${CIPHERFIX_CONTAINER}":/cipherfix/

docker cp ./mitigation_scripts/analyze-reenc_e2e_engine_mueoc.sh "${CIPHERFIX_CONTAINER}":/cipherfix/
docker cp ./mitigation_scripts/analyze-reenc_e2e_engine_lwe.sh "${CIPHERFIX_CONTAINER}":/cipherfix/
docker cp ./mitigation_scripts/analyze-reenc_e2e_engine_slot_mueoc.sh "${CIPHERFIX_CONTAINER}":/cipherfix/

docker cp ./mitigation_scripts/instrument-reenc_e2e_engine_mueoc.sh "${CIPHERFIX_CONTAINER}":/cipherfix/
docker cp ./mitigation_scripts/instrument-reenc_e2e_engine_lwe.sh "${CIPHERFIX_CONTAINER}":/cipherfix/
docker cp ./mitigation_scripts/instrument-reenc_e2e_engine_slot_mueoc.sh "${CIPHERFIX_CONTAINER}":/cipherfix/

docker cp ./mitigation_scripts/apply_mitigation_mueoc.sh "${CIPHERFIX_CONTAINER}":/cipherfix/

docker exec -e N="${N}" "${CIPHERFIX_CONTAINER}" /bin/bash -lc '
mkdir -p /constantine/src/build
cd /cipherfix
chmod +x *
./apply_mitigation_mueoc.sh ${N}
'

mkdir -p ./build
docker cp "${CIPHERFIX_CONTAINER}":/constantine/src/build/ ./
docker cp "${CIPHERFIX_CONTAINER}":/lib/x86_64-linux-gnu/ld-2.31.so ./build/ld-linux-x86-64.so.2
chmod +x ./build/ld-linux-x86-64.so.2 \
         ./build/reenc_e2e_engine_mueoc/reenc_e2e_engine_mueoc \
         ./build/reenc_e2e_engine_lwe/reenc_e2e_engine_lwe \
         ./build/reenc_e2e_engine_slot_mueoc/reenc_e2e_engine_slot_mueoc \
         ./build/reenc_e2e_engine_mueoc/libc.so.6.instr \
         ./build/reenc_e2e_engine_mueoc/libm.so.6.instr \
         ./build/reenc_e2e_engine_lwe/libc.so.6.instr \
         ./build/reenc_e2e_engine_lwe/libm.so.6.instr \
         ./build/reenc_e2e_engine_slot_mueoc/libc.so.6.instr \
         ./build/reenc_e2e_engine_slot_mueoc/libm.so.6.instr
echo "[+] MUEOC mitigation and build completed for N=${N}"
