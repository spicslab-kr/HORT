#!/bin/bash
set -e

N=${1:-64}

cd cipherfix
# ./instrument.sh /cipherfix/openfhe-development/build/bin/examples/pke fast aesrng
./instrument.sh /constantine/src/reenc_e2e_lwe/reenc_e2e_engine_lwe_N${N} enhanced aesrng