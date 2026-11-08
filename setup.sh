#!/bin/bash
# Step
# 1. Setup Cipherfix Docker environment
# 2. Setup Ubuntu 18.04 to install Constantine
# 3. docker exec -it constantine /bin/bash
# 4. apt-get install -y make, python, build-essential, clang-9, git, wget, pin314, vim, cmake, ninja-build, curl && git clone constantine
# 5. build constantine
# 6. tar constantine , docker cp constantine:/constantine.tar cipherfix:/constantine.tar
# 7. docker stop constantine && docker remove constantine
# 8. docker apt install -y python3-pip clang-9 libtinfo5
# 9. patch diff 

#!/usr/bin/env bash
set -euo pipefail

ART_DIR="$PWD/artifacts"
mkdir -p "$ART_DIR"

# 1) 기존에 돌아가는 'cipherfix' 컨테이너가 있다면 무조건 삭제 (깨끗한 시작)
echo "[Step 0] Installing Docker and prequistes..."

# sudo apt update
# sudo apt -y install apt-transport-https ca-certificates curl software-properties-common
# curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
# sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu bionic stable"
# sudo apt update

# # 도커가 설치 되었는지 확인
# apt-cache policy docker-ce

# # Installed : none
# sudo apt -y install docker-ce

# sudo systemctl start docker
# sudo systemctl enable docker


# 1) 기존에 돌아가는 'cipherfix' 컨테이너가 있다면 무조건 삭제 (깨끗한 시작)
echo "[Step 1] Cleaning up existing cipherfix container..."
docker rm -f cipherfix 2>/dev/null || true

# 2) cipherfix 컨테이너 실행
echo "[Step 2] Starting fresh cipherfix container..."
docker run -d -it --name cipherfix \
  ghcr.io/uzl-its/cipherfix-examples-full:latest

# 3) constantine 빌드 (완료 후 --rm에 의해 컨테이너 자동 삭제됨)
echo "[Step 3] Building Constantine in temporary container..."
docker run --rm --name constantine-builder \
  -v "$ART_DIR:/artifacts" \
  ubuntu:18.04 bash -lc '
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y --no-install-recommends \
  ca-certificates curl wget git \
  make build-essential cmake ninja-build \
  python3 python3-pip \
  clang-9 llvm-9-dev

git clone https://github.com/pietroborrello/constantine.git /constantine
git config --global user.email "root@local"
git config --global user.name "root"
cd /constantine/src

chmod +x *
./install.sh
. ./setup.sh
./llvm_compile_dfsan_cpp.sh

(cd passes && make install)
(cd lib && make install)

cd /constantine
tar -czf /artifacts/constantine.tar.gz .
'

# 4) artifacts에 있는 tar를 cipherfix로 복사
echo "[Step 4] Migrating constantine baseline to cipherfix"
docker cp "$ART_DIR/constantine.tar.gz" cipherfix:/tmp/constantine.tar.gz
rm -rf $ART_DIR/constantine.tar.gz

# 5) cipherfix 컨테이너 안에서 환경 세팅 및 압축 풀기
docker exec -u root cipherfix bash -lc '
set -euo pipefail
apt-get update
apt-get install -y python3-pip clang-9 libtinfo5 git patch lld-9 || true

mkdir -p /constantine
tar -xzf /tmp/constantine.tar.gz -C /constantine
pip3 install click
'
docker cp ./cipherfix_interface_san.o cipherfix:/constantine/src/
docker cp ./cipherfix_interface_nosan.o cipherfix:/constantine/src/
docker cp ./cipherfix_interface.c cipherfix:/cipherfix/cipherfix/
docker cp ./cipherfix_interface.h cipherfix:/cipherfix/cipherfix/

# 6) Patch 적용 (0001 제외 로직이 포함된 외부 스크립트 호출)
# 주의: 이전에 만든 apply_patches.sh에 0001 제외 로직이 있어야 합니다.
echo "[Step 6] Applying patches..."
bash "$(dirname "$0")/apply_patches.sh"

# 7) 빌드 (Constantine + Cipherfix)

echo "[Step 7] Final building inside cipherfix container..."
docker exec -u root cipherfix bash -lc '
set -euo pipefail

apt-get install lld-9
cd /constantine/src
. ./setup.sh
(cd /constantine/src/passes && make install)
(cd /constantine/src/lib && make install)

cd /cipherfix/cipherfix
./build-all.sh

echo "=== ALL PROCESS COMPLETED SUCCESSFULLY ==="
'

docker exec -it cipherfix /bin/bash