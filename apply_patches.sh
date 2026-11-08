#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
PATCH_DIR="$ROOT_DIR"
CIPHERFIX_CONTAINER="${CIPHERFIX_CONTAINER:-cipherfix}"


# 2. 컨테이너 내부로 패치 파일 전송
docker exec "$CIPHERFIX_CONTAINER" bash -lc 'mkdir -p /tmp/patches'
docker cp constantine_all.patch cipherfix:/tmp/patches/
docker cp cipherfix_only.patch cipherfix:/tmp/patches/


# 3. 내부 패치 실행 및 빌드 경로 수정
docker exec -i "$CIPHERFIX_CONTAINER" bash -s <<'EOF'
set -x 
set -euo pipefail

PATCH_DIR=/tmp/patches
CONSTANTINE_DIR="/constantine"

echo "=== [DEBUG] Starting patch and build logic inside container ==="

find_cipherfix_dir() {
  for d in /cipherfix/cipherfix /cipherfix /opt/cipherfix /root/cipherfix /workspace/cipherfix; do
    if [ -d "$d" ]; then echo "$d"; return 0; fi
  done
  return 1
}
CIPHERFIX_DIR="$(find_cipherfix_dir || true)"

# A. Cipherfix 패치 (기존 유지)
if [ -f "$PATCH_DIR/cipherfix_only.patch" ]; then
  sed -e "s|^diff -ruN ./original/|diff -ruN |" \
      -e "s| ./modified/cipherfix/| |" \
      -e "s|^--- ./original/|--- |" \
      -e "s|^\\+\\+\\+ ./modified/cipherfix/|+++ |" \
      "$PATCH_DIR/cipherfix_only.patch" > "$PATCH_DIR/cipherfix_only.norm.patch"

  awk '/^diff -ruN / { p1 = $3; p2 = $4; skip = (p1 ~ /\.(o|a|so|bcc)$/) || (p2 ~ /\.(o|a|so|bcc)$/) } { if (!skip) print }' \
      "$PATCH_DIR/cipherfix_only.norm.patch"c > "$PATCH_DIR/cipherfix_only.src.patch"

  (cd "$CIPHERFIX_DIR" && patch -p0 --binary --forward < "$PATCH_DIR/cipherfix_only.src.patch" || true)
fi

# B. Constantine 패치 (git apply)
# apply_patches.sh 내부의 apply_git_patch 함수 수정본
cd /constantine
patch -p1 < /tmp/patches/constantine_all.patch
echo "=== [SUCCESS] Patches applied and Build completed ==="

EOF