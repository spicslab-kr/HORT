# This script is applies mitigation and build binaries at Docker environment

#!/bin/bash

set -e

N=${1:-64}
CIPHERFIX_CONTAINER=${CIPHERFIX_CONTAINER:-cipherfix}
echo "[+] Applying Mitigations for N=${N}"

# Step 1. cp reenc_e2e_engine sources to Docker enivironment
docker exec "${CIPHERFIX_CONTAINER}" /bin/bash -lc 'mkdir -p /constantine/src/reenc'
docker cp ./src_engine/reenc_e2e_engine_lwe.c "${CIPHERFIX_CONTAINER}":/constantine/src/reenc/
docker cp ./src_engine/reenc_e2e_engine_slot.c "${CIPHERFIX_CONTAINER}":/constantine/src/reenc/
docker cp ./src_engine/reenc_e2e_engine.c "${CIPHERFIX_CONTAINER}":/constantine/src/reenc/

docker cp ./mitigation_scripts/all-in-one-reenc_e2e_engine.sh "${CIPHERFIX_CONTAINER}":/cipherfix/
docker cp ./mitigation_scripts/all-in-one-reenc_e2e_engine_lwe.sh "${CIPHERFIX_CONTAINER}":/cipherfix/
docker cp ./mitigation_scripts/all-in-one-reenc_e2e_engine_slot.sh "${CIPHERFIX_CONTAINER}":/cipherfix/

docker cp ./mitigation_scripts/analyze-reenc_e2e_engine.sh "${CIPHERFIX_CONTAINER}":/cipherfix/
docker cp ./mitigation_scripts/analyze-reenc_e2e_engine_lwe.sh "${CIPHERFIX_CONTAINER}":/cipherfix/
docker cp ./mitigation_scripts/analyze-reenc_e2e_engine_slot.sh "${CIPHERFIX_CONTAINER}":/cipherfix/

docker cp ./mitigation_scripts/instrument-reenc_e2e_engine.sh "${CIPHERFIX_CONTAINER}":/cipherfix/
docker cp ./mitigation_scripts/instrument-reenc_e2e_engine_lwe.sh "${CIPHERFIX_CONTAINER}":/cipherfix/
docker cp ./mitigation_scripts/instrument-reenc_e2e_engine_slot.sh "${CIPHERFIX_CONTAINER}":/cipherfix/

docker cp ./mitigation_scripts/apply_mitigation.sh "${CIPHERFIX_CONTAINER}":/cipherfix/

# Step 2. Execute mitigation inside the container.

docker exec -e N="${N}" "${CIPHERFIX_CONTAINER}" /bin/bash -lc '
mkdir -p /constantine/src/build
cd /cipherfix
chmod +x *
./apply_mitigation.sh "${N}"
'

# Step 3. mv execution files from Docker to SEV
mkdir -p ./build
# docker cp cipherfix:/constantine/src/build/reenc_e2e_engine_N${N}.out.instr ./build/reenc_e2e_engine
# docker cp cipherfix:/constantine/src/build/reenc_e2e_engine_lwe_N${N}.out.instr ./build/reenc_e2e_engine_lwe
# docker cp cipherfix:/constantine/src/build/reenc_e2e_engine_slot_N${N}.out.instr ./build/reenc_e2e_engine_slot
docker cp "${CIPHERFIX_CONTAINER}":/constantine/src/build/ ./
docker cp "${CIPHERFIX_CONTAINER}":/lib/x86_64-linux-gnu/ld-2.31.so ./build/ld-linux-x86-64.so.2
chmod +x ./build/reenc_e2e_engine/reenc_e2e_engine \
         ./build/ld-linux-x86-64.so.2 \
         ./build/reenc_e2e_engine_lwe/reenc_e2e_engine_lwe \
         ./build/reenc_e2e_engine_slot/reenc_e2e_engine_slot \
         ./build/reenc_e2e_engine/libc.so.6.instr \
         ./build/reenc_e2e_engine/libm.so.6.instr \
         ./build/reenc_e2e_engine_lwe/libc.so.6.instr \
         ./build/reenc_e2e_engine_lwe/libm.so.6.instr \
         ./build/reenc_e2e_engine_slot/libc.so.6.instr \
         ./build/reenc_e2e_engine_slot/libm.so.6.instr
# scp -R  ./build_engine/* sev:/build/
echo "[+] Mitigation and Build Completed for N=${N}"
