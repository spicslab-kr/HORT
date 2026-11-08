#!/bin/bash
set -e

N=${1:-16384}
echo "[+] Building DB reenc_e2e_engine_slot for N=${N}"
cd /constantine/src
. ./setup.sh

cd /constantine/src/reenc
./../constantine -O0 -N${N} /constantine/src/reenc/reenc_e2e_engine_slot_db.c -o reenc_e2e_engine_slot_db_N${N}

rm -rf ../reenc_e2e_slot_db/reenc_e2e_engine_slot_db_N${N}/*
mkdir -p ../reenc_e2e_slot_db/reenc_e2e_engine_slot_db_N${N}
mv ./reenc_e2e_engine_slot_db_N${N}.out ../reenc_e2e_slot_db/reenc_e2e_engine_slot_db_N${N}/reenc_e2e_engine_slot_db_N${N}.out

cd /cipherfix

pattern="${2:-^[[:space:]]*reenc_e2e_engine_slot_db_N${N}.out|^[[:space:]]*libc.so.6}"
out_file="${3:-/constantine/src/reenc_e2e_slot_db/reenc_e2e_engine_slot_db_N${N}/structure.out}"

sh analyze-reenc_e2e_engine_slot_db.sh ${N}
sh instrument-reenc_e2e_engine_slot_db.sh ${N} | tee instrument.log |
  awk -v pattern="$pattern" -v outfile="$out_file" '
    $0 ~ pattern {
      line = $0
      sub(/^[[:space:]]+/, "", line)
      n = split(line, fields, /[[:space:]]+/)
      if (n == 0) {
        next
      }
      key = fields[1]
      sub(/\+.*/, "", key)
      if (key == "") {
        next
      }
      if (seen[key]) {
        next
      }
      for (i = 1; i <= NF; ++i) {
        if ($i ~ /^M\*/ && i + 1 <= NF) {
          addr = $(i + 1)
          sub(/\*/, "m", $i)
          printf "%s %s\n", $i, addr >> outfile
          seen[key] = 1
          break
        }
      }
      for (j in fields) {
        delete fields[j]
      }
    }
  '

sh instrument-reenc_e2e_engine_slot_db.sh ${N}

mkdir -p /constantine/src/build/reenc_e2e_engine_slot_db
cp /constantine/src/reenc_e2e_slot_db/reenc_e2e_engine_slot_db_N${N}/instr-enhanced-aesrng/reenc_e2e_engine_slot_db_N${N}.out.instr /constantine/src/build/reenc_e2e_engine_slot_db/reenc_e2e_engine_slot_db
cp /constantine/src/reenc_e2e_slot_db/reenc_e2e_engine_slot_db_N${N}/instr-enhanced-aesrng/libc.so.6.instr /constantine/src/build/reenc_e2e_engine_slot_db/
cp /constantine/src/reenc_e2e_slot_db/reenc_e2e_engine_slot_db_N${N}/instr-enhanced-aesrng/libm.so.6.instr /constantine/src/build/reenc_e2e_engine_slot_db/
