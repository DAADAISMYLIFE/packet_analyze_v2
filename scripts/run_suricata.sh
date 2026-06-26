#!/usr/bin/env bash
# pcap -> Suricata eve.json (alert 포함)
# 사용법: ./run_suricata.sh <pcap파일>
set -euo pipefail

PCAP="${1:?사용법: run_suricata.sh <pcap파일>}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PCAP_ABS="$(realpath "$PCAP")"
PCAP_NAME="$(basename "$PCAP_ABS")"
NAME="${PCAP_NAME%.*}"
OUT="$ROOT/output/suricata/$NAME"

# 실행 전 출력 청소 (eve-log append=yes라 재실행 시 누적 → 숫자 오염 방지)
rm -rf "$OUT"
mkdir -p "$OUT"
echo "[suricata] $PCAP_NAME -> $OUT"

# 로컬 설치된 suricata 사용 (ET Open 룰 로딩됨)
# --set outputs.1.eve-log.community-id=true : Zeek conn.log와 조인할 community_id 활성화
#   (Zeek/Suricata 둘 다 seed=0이라 같은 flow에 동일 해시 → 100% 매칭)
# --set outputs.1.eve-log.append=false : 누적 방지 이중 안전장치 (청소와 별개로)
suricata -r "$PCAP_ABS" -l "$OUT" -k none \
  --set outputs.1.eve-log.community-id=true \
  --set outputs.1.eve-log.append=false 2>&1 | tail -1

echo "[suricata] alert 개수:"
grep -c '"event_type":"alert"' "$OUT/eve.json" 2>/dev/null || echo 0
echo "[suricata] 완료 -> $OUT/eve.json"
