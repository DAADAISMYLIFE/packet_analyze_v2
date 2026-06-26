#!/usr/bin/env bash
# pcap -> Zeek JSON 로그
# 사용법: ./run_zeek.sh <pcap파일>
set -euo pipefail

PCAP="${1:?사용법: run_zeek.sh <pcap파일>}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PCAP_ABS="$(realpath "$PCAP")"
PCAP_DIR="$(dirname "$PCAP_ABS")"
PCAP_NAME="$(basename "$PCAP_ABS")"
NAME="${PCAP_NAME%.*}"
OUT="$ROOT/output/zeek/$NAME"

# 실행 전 출력 청소 (재실행 시 이전 로그/추출파일 누적 방지)
rm -rf "$OUT"
mkdir -p "$OUT"
echo "[zeek] $PCAP_NAME -> $OUT"

# JSON 로그로 출력 (LLM 파싱 편하게), 결과는 OUT 폴더에 떨어짐
# --user : host 유저 권한으로 실행 (root 소유 파일 생성 방지 → 청소 가능)
# 추가 기능:
#   community-id-logging  : conn.log에 community_id (Suricata alert와 정확 매칭용)
#   hash-all-files        : files.log에 md5/sha1/sha256 (멀웨어 식별용)
#   extract-all-files     : 다운로드된 실제 파일을 extract_files/로 추출(carve)
# 읽기 실패(지원 안 하는 포맷 등)해도 파이프라인 중단 없이 빈 출력으로 진행
if docker run --rm \
  --user "$(id -u):$(id -g)" \
  -v "$PCAP_DIR":/pcap:ro \
  -v "$OUT":/out \
  -w /out \
  zeek/zeek:latest \
  zeek -C -r "/pcap/$PCAP_NAME" LogAscii::use_json=T \
    policy/protocols/conn/community-id-logging \
    policy/protocols/conn/mac-logging \
    policy/frameworks/files/hash-all-files \
    policy/frameworks/files/extract-all-files
then
  echo "[zeek] 완료. 생성된 로그:"
  ls -1 "$OUT"
else
  echo "[zeek] ❌ 읽기 실패 — 지원 안 하는 캡처 포맷일 수 있음 (빈 출력으로 진행)"
fi
