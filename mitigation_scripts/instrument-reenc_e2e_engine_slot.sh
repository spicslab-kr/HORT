#!/bin/bash
set -e

N=${1:-64}

cd cipherfix
# ./instrument.sh /cipherfix/openfhe-development/build/bin/examples/pke fast aesrng
./instrument.sh /constantine/src/reenc_e2e_slot/reenc_e2e_engine_slot_N${N} enhanced aesrng