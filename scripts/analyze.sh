#!/usr/bin/env bash
# pcap 1개를 끝까지 분석하는 단일 진입점.
#   패킷수 측정 → Suricata → Zeek → compress(evidence package + 상태)
# 어떤 단계가 실패해도 멈추지 않고, 최종 evidence package에 status로 기록한다.
# 사용법: ./analyze.sh <pcap파일>
set -uo pipefail   # -e 제외: 단계 실패해도 끝까지 진행 후 status로 보고

PCAP="${1:?사용법: analyze.sh <pcap파일>}"
DIR="$(cd "$(dirname "$0")" && pwd)"
NAME="$(basename "$PCAP")"; NAME="${NAME%.*}"

echo "═══ analyze: $NAME ═══"

# 0. 입력 패킷 수 (libpcap 기준. 지원 안 하는 포맷이면 0 → 상태 판정에 사용)
PKTS="$(tcpdump -r "$PCAP" 2>/dev/null | wc -l)"
echo "[0] 입력 패킷: $PKTS"
if [ "$PKTS" -eq 0 ]; then
  echo "    ⚠️  패킷 0 — 지원 안 하는 포맷일 수 있음 (그래도 끝까지 진행해 status 남김)"
fi

# 1. Suricata (시그니처)
bash "$DIR/run_suricata.sh" "$PCAP" 2>&1 | sed 's/^/    /'

# 2. Zeek (flow + 파일추출 + community_id)
bash "$DIR/run_zeek.sh" "$PCAP" 2>&1 | tail -3 | sed 's/^/    /'

# 3. 압축 → evidence package (+ 상태 스탬프)
echo "[3] compress"
python3 "$DIR/compress.py" "$NAME" --pkts "$PKTS" --md 2>&1 | sed 's/^/    /'
