# packet_analyze_v2 — 완전 자동화 보안 분석 AI

pcap 파일을 받아 **공격 패킷 여부 / CVE·멀웨어 / 공격자·C2 IP**를 자동 분석하는 로컬 sLLM 파이프라인.
사람 개입 없이 높은 신뢰성·정확도를 목표로 한다.

## 핵심 설계 철학

> **LLM이 원본 패킷(수백만 건)을 직접 보지 않는다.**
> Zeek/Suricata로 1차 구조화 → 코드로 통계 압축 → LLM은 "수천 토큰짜리 요약(evidence package)"만 본다.

- **결정론적 압축**: 같은 입력 → 항상 같은 출력. 압축 단계에 LLM·랜덤 없음 (재현성/신뢰성).
- **근거 보존**: 모든 플래그에 *왜*(숫자)를 같이 담아 검증 가능하게.
- **실패를 실패라고 말한다**: 못 읽는 입력이 "정상(이상 없음)"으로 둔갑하지 않도록 status로 명시.

---

## 디렉토리 구조 — 왜 이렇게 되어있나

```
packet_analyze_v2/
├── pcaps/          # [입력] 분석할 pcap 원본
├── output/         # [중간 산출물] 도구별로 분리 보관
│   ├── suricata/<name>/   # eve.json(alert 등), fast.log, stats.log
│   └── zeek/<name>/       # conn.log, http.log ... + extract_files/(추출된 실제 파일)
├── report/         # [최종 산출물] <name>.evidence.json (+ .md) — LLM 입력
├── config/         # (예약) 커스텀 설정 — 현재는 시스템 설정 사용
├── rag/            # (예약) RAG/Vector DB — CVE·IOC 매칭 단계용
├── scripts/        # 실행 스크립트 (아래 설명)
└── README.md
```

**설계 의도:**
- **입력 / 중간 산출물 / 최종 산출물을 물리적으로 분리** → 단계별 디버깅·재실행이 쉬움.
- `output/`을 도구별·pcap별로 폴더 분리 → 여러 pcap을 섞이지 않게 병렬 처리 가능.
- `report/`만 보면 LLM에 무엇이 들어가는지 명확 (원본/중간물과 격리).
- `rag/`는 다음 단계(CVE 매칭) 자리만 잡아둔 것.

---

## scripts/ — 파일별 역할

| 파일 | 역할 |
|---|---|
| **analyze.sh** | **단일 진입점.** pcap 1개를 끝까지 분석 (패킷수 측정 → Suricata → Zeek → compress). 어떤 단계가 실패해도 멈추지 않고 최종 status로 보고 |
| **run_suricata.sh** | pcap → Suricata 시그니처 탐지 → `eve.json` |
| **run_zeek.sh** | pcap → Zeek flow 구조화 → 로그 + 파일추출 + community_id + MAC |
| **compress.py** | Zeek/Suricata 로그 → **evidence package**(LLM 입력)로 압축 |
| **tools.py** | LLM function-calling용 **드릴다운 도구** 7종 (원본 로그 조회, 읽기전용) |
| **llm_analyze.py** | evidence package → LLM 판정(**verdict**). OpenAI 호환, tool 루프, Colab/클라우드 포터블 |

### analyze.sh
```bash
./analyze.sh pcaps/<파일>.pcap
```
1. `tcpdump -r`로 입력 패킷 수 측정 (libpcap이 못 읽는 포맷이면 0 → 상태 판정에 사용)
2. `run_suricata.sh` 실행
3. `run_zeek.sh` 실행
4. `compress.py --pkts N` 실행 → `report/<name>.evidence.json`
- `set -uo pipefail` (**-e 제외**): 단계가 실패해도 중단하지 않고 끝까지 가서 status로 남긴다.

### run_suricata.sh
- ET Open 룰(66k개)로 알려진 공격 시그니처 탐지.
- **실행 전 출력 디렉토리 청소** + `--set outputs.1.eve-log.append=false`
  → eve-log가 `append: yes` 기본값이라 재실행 시 alert가 누적·오염되는 버그를 이중으로 차단.
- `--set outputs.1.eve-log.community-id=true`
  → Zeek와 동일한 community_id 해시를 찍어 **flow 단위 조인**을 가능하게 함 (둘 다 seed=0).

### run_zeek.sh
- flow 구조화 + JSON 로그(`LogAscii::use_json=T`)로 출력 (LLM/pandas 파싱 용이).
- **실행 전 출력 청소** (재실행 시 extract_files 누적 방지).
- `--user $(id -u):$(id -g)` → 도커가 root로 파일 만들어 host가 못 지우는 문제 방지.
- 활성화한 Zeek 고급 기능:
  - `community-id-logging` : conn.log에 `community_id` (Suricata alert와 정확 매칭)
  - `mac-logging` : conn.log에 `orig_l2_addr`/`resp_l2_addr` (MAC — 호스트 신원조회)
  - `hash-all-files` : files.log에 md5/sha256 (멀웨어 신원조회 입력)
  - `extract-all-files` : 다운로드된 실제 파일을 `extract_files/`로 carve
- 읽기 실패(지원 안 하는 포맷)해도 파이프라인 중단 없이 빈 출력으로 진행.

---

## compress.py — 내부 구조 상세

**목적**: 수십 MB·수만 이벤트의 Zeek/Suricata 로그를 **결정론적으로 압축**해 LLM이 한 번에 볼 수 있는
`evidence package`(JSON, 수천 토큰)로 만든다.

### 아키텍처: 2층 + 폴백

```
1층(백본, 프로토콜 무관)  : Suricata alert + conn.log 통계 + 탐지기(비콘/스캔/측면이동)
                            → conn.log엔 모든 flow가 모이므로 어떤 프로토콜이 와도 동작
2층(enrichment, 있으면)   : http/dns/files/ssl 전용 압축기
폴백                      : 등록 안 된 로그는 generic()이 "줄 수 + top값"으로 자동 처리
```

### 설정 상수 (탐지 임계값 — 한 곳에서 관리, 발표 시 근거)

| 상수 | 값 | 의미 |
|---|---|---|
| `BEACON_MIN_CONNS` | 5 | 비콘 판정 최소 연결 수 |
| `BEACON_CV_MAX` | 0.10 | 연결 간격 변동계수(CV) 이하면 '규칙적' = 비콘 |
| `SCAN_MIN_PORTS` | 15 | 한 src가 한 dst에서 이만큼 포트 두드리면 스캔 |
| `LATERAL_PORTS` | 445,88,389,135,3389,5985 | 측면이동 신호 포트(SMB/Kerberos/LDAP/RPC/RDP/WinRM) |
| `ALERT_CLASS_RULES` | (접두사 목록) | alert를 threat/suspicious/info/engine 4버킷으로 분류 |
| `NOISE_BUCKET_LIMIT` | 15 | info/engine 노이즈 버킷만 이 개수로 truncate |

### 함수별 용도

#### 공통 유틸
| 함수 | 용도 |
|---|---|
| `read_zeek_log(path)` | Zeek JSON 로그 1개 → dict 리스트. 파일 없으면 `[]`(안전) |
| `read_eve(path)` | Suricata eve.json → `event_type`별로 분류한 dict |
| `is_private(ip)` | 사설 IP 여부 — 내부/외부 통신 구분(C2는 보통 외부) |
| `shannon_entropy(s)` | 문자열 엔트로피 — DGA(랜덤 도메인) 탐지용 |

#### 1층: 백본
| 함수 | 용도 |
|---|---|
| `classify_alert(sig, severity)` | 시그니처 접두사로 4버킷 분류 (`ET MALWARE`→threat, `SURICATA `→engine 등). **접두사 미매칭 시 Suricata severity를 backstop**(1→threat/2→suspicious/3→info)으로 사용 → 손으로 만든 목록에서 빠진 위협(예: `ET RPC` sev1)이 숨는 사각지대 제거 |
| `compress_alerts(alerts, top)` | alert를 **2단 압축**: ①`by_signature`(시그니처별 총합=헤드라인) ②`by_flow`(community_id별 상세=조인용). **위협/의심은 절대 truncate 안 함**(1회짜리 치명적 alert 보존), info/engine 노이즈만 자름 |
| `compress_conn(conn, top)` | conn.log를 `(src,dst,dport)`로 묶어 통계화. **비콘**(간격 CV), **top-talker**(외부 대용량), **측면이동**(내부→내부 AD포트), **포트스캔** 탐지. *전부 프로토콜 무관* |
| `join_alert_to_flow(rows, conn)` | community_id로 alert에 flow 맥락(service/duration/bytes/state) 부착 |
| `build_timeline(conn, alerts, files, top)` | **실제 ts 기반 공격 흐름 뼈대.** 세션범위/멀웨어다운로드/위협시그니처 첫발생/비콘 시각을 시간순 정렬. alert는 community_id로 conn의 실제 ts에 앵커링 → **LLM은 해석만, 시간은 안 지어냄** |
| `build_host_profiles(conn, ntlm, kerberos, top)` | **IP별 신원 통합**(내부 호스트만). conn에서 MAC/연결수, ntlm/kerberos에서 호스트명·도메인·유저 → IP가 "DESKTOP-xxx / user"가 됨 |

#### 2층: enrichment (해당 로그 있을 때만 동작)
| 함수 | 용도 |
|---|---|
| `compress_http(http, top)` | host/UA 묶기 + **실행파일 다운로드·dotted-quad로 POST** 등 의심 플래그 |
| `compress_dns(dns, top)` | query 묶기 + **고엔트로피(DGA)·외부IP조회** 도메인 플래그 |
| `compress_files(files, top)` | 실행파일만 추려 **SHA256으로 dedup**(멀웨어 후보). 불완전 추출은 카운트만 |
| `compress_ssl(ssl, top)` | JA3 핑거프린트 집계 + 인증서 검증 실패 플래그 |

#### 폴백 & 등록부
| 항목 | 용도 |
|---|---|
| `generic(rows, top)` | **등록 안 된 모든 로그 처리.** 식별자 제외, 카디널리티 낮은 컬럼의 top값만 요약 → 처음 보는 프로토콜 로그가 와도 안 깨짐 |
| `REGISTRY` | `{로그명: 전용압축기}` 매핑. 없으면 `generic`으로 자동 fallback |

#### 상태 판정 & 조립
| 함수 | 용도 |
|---|---|
| `assess_status(...)` | 파이프라인 건강 판정. `FAILED_TO_PARSE`(못 읽음) / `NO_IP_FLOWS`(비IP) / `OK` 3분리 → **실패가 '정상'으로 위장하는 것 차단** |
| `build_evidence(name, zeek_dir, eve_path, top, pkts)` | 전체 조립. 1층→2층→폴백→상태 순으로 evidence package 완성 |
| `to_markdown(pkg)` | 사람용 요약(.md) 생성 (위협 우선, 노이즈 생략) |
| `main()` | CLI 파싱 → 빌드 → `report/<name>.evidence.json` 저장 (+`--md`) |

### evidence package 출력 구조
```json
{
  "meta": { "status":"OK", "input_packets":N, "flows":N,
            "alert_buckets":{...}, "warnings":[...] },
  "ids_alerts":    { "by_signature":[...], "by_flow":[...], "bucket_counts":{...} },
  "conn":          { "beaconing":[...], "top_talkers_external":[...],
                     "lateral_movement":[...], "port_scans":[...] },
  "host_profiles": { "<ip>":{ "hostname":..,"domain":..,"user":..,"mac":..,"conns":N } },
  "timeline":      [ { "clock":"HH:MM:SS","offset":"+Ns","event":..,"evidence":.. } ],
  "enrichment":    { "http":{...}, "dns":{...}, "files":{...}, "ssl":{...} },
  "other_protocols": { "<로그>":{ "records":N, "top_values":{...} } }
}
```

### 사용법
```bash
# 단일 진입점 (권장)
./scripts/analyze.sh pcaps/<파일>.pcap

# compress 단독 실행 (이미 zeek/suricata 산출물이 있을 때)
python3 scripts/compress.py <name> --pkts <패킷수> --md
#   --top N : 각 목록 상위 N개 (기본 20)
#   --md    : 사람용 markdown도 출력
```

---

## tools.py — LLM 드릴다운 도구 (티어③)

LLM은 평소 evidence package(요약)만 본다. **더 깊이 봐야 할 때만** 아래 도구를 호출해
디스크의 원본 Zeek/Suricata 로그에서 해당 부분만 꺼내온다 (읽기 전용, 출력 limit).

| 도구 | 용도 |
|---|---|
| `get_flow_detail(community_id)` | 특정 flow의 conn/http/dns/ssl/files 원본 (uid로 로그 간 상관) |
| `search_http(host, uri_contains)` | HTTP 요청 원본 검색 |
| `search_dns(query_contains)` | DNS 질의 원본 검색 |
| `search_alerts(signature_contains, src, dst)` | Suricata alert 원문 검색 |
| `get_connections_by_ip(ip)` | 특정 IP가 관여한 flow 전부 |
| `get_malware_file(sha256)` | 추출된 멀웨어 파일 메타 + 디스크 경로 |
| `get_host_info(ip, mac)` | 호스트 신원(호스트명/도메인/유저/MAC) |

- `DrillDownTools(name)` : pcap당 1개 인스턴스. 로그를 캐시해 재사용.
- `TOOL_SCHEMAS` : OpenAI/Ollama 호환 function-calling 스키마.
- `dispatch(tools, name, args)` : LLM 호출 → 메서드 라우팅.
- 단독 테스트: `python3 scripts/tools.py <name>`

## llm_analyze.py — LLM 판정 단계

evidence package를 LLM에 주고 최종 판정(verdict)을 받는다.

- **OpenAI 호환 API**로 통신 → Colab Ollama(localhost)든 GPU 클라우드든 `--base-url`만 바꾸면 동작 (포터블).
- LLM은 **슬림 evidence**(요약+타임라인+신원+멀웨어, ~4.5k 토큰)만 받고, 더 봐야 하면 `tools.py` 드릴다운 호출.
- 판정은 **`submit_verdict` 도구 호출**로 제출 → 구조화 출력 강제 (자유텍스트 파싱 안 함).
- `needs_review`는 **코드가 강제** (`enforce_review`): confidence≠high 또는 unknown_anomaly → true.

```bash
# Colab/서버 (Ollama 떠 있을 때)
python3 scripts/llm_analyze.py <name> --base-url http://localhost:11434/v1 \
    --model qwen2.5:14b
# GPU 없이 프롬프트/배선/토큰만 점검
python3 scripts/llm_analyze.py <name> --dry-run
```

### 실행 환경 분리 (중요)

```
[로컬 PC] GPU 불필요          [Colab T4] GPU 필요
analyze.sh → evidence.json  ─GitHub─→  llm_analyze.py → verdict.json
```
- 수집·압축(suricata/zeek/compress)은 **로컬**. evidence.json만 GitHub에 push.
- LLM 판정만 **Colab**(`notebooks/colab_llm.ipynb`): repo clone → Ollama(qwen2.5:14b) 부팅 → 판정.
- `.gitignore`가 대용량(pcap/output)은 제외하고 **`report/*.evidence.json`만** 올리도록 설정됨.

## verdict 스키마 (LLM 판정 출력)

`submit_verdict` 도구로 제출되는 최종 판정 형식:
```json
{
  "is_attack": true,
  "classification": "known_threat",        // known_threat | unknown_anomaly | benign
  "confidence": "high",                     // high | medium | low (범주형)
  "malware_family": "Hancitor", "cve": [],
  "threat_actors": { "victim_ips":[..], "attacker_ips":[..], "c2":[{ip,domain,evidence}] },
  "mitre_attack": [{tactic,technique,evidence}],   // 풍부 — 단 확실한 것만
  "timeline": [...],                        // compress.py 뼈대를 LLM이 해석
  "kill_chain_summary": "...", "reasoning": "...", "evidence_refs": [...],
  "needs_review": false                     // 코드가 강제: confidence!=high or unknown → true
}
```
설계 원칙: MITRE/timeline은 **모르면 빈 값**(환각 방지), `needs_review`는 **LLM이 아니라 코드가 강제**.

---

## 환경

- Suricata 8.0.5 (ET Open 룰) — 로컬 설치, `suricata` 그룹 권한 필요
- Zeek 8.2.0 — `zeek/zeek:latest` 도커 이미지
- Python 3 (표준 라이브러리만 사용, 외부 의존성 없음)

## 검증된 동작 (실측, 8개 pcap 무crash)

| 입력 | 결과 |
|---|---|
| ISC 포렌식 (200,929 패킷, Hancitor 감염) | ✅ OK. 55MB→45KB(**~1221배 압축**). CS 비콘·멀웨어 SHA256 3종·타임라인·신원(tommy.vega/DESKTOP-NIEE9LP) 탐지 |
| ISC 챌린지 (84,542 패킷) | ✅ OK. NanoCore RAT·측면이동(SVCCTL) 탐지 |
| traffic-analysis (16,296 패킷) | ✅ OK. IcedID 탐지 (1회짜리도 보존) |
| Sniffer/NetMon `.cap` (비표준 포맷) | ❌ FAILED_TO_PARSE (위장 차단) |
| LINX (비IP 프로토콜) | ⚠️ NO_IP_FLOWS |

## 진행 현황

```
[수집] suricata + zeek          ✅
[압축] compress.py              ✅  (alert분류 / 비콘·측면이동 / 멀웨어해시 / timeline / host_profiles)
[드릴다운] tools.py             ✅  (7개 도구)
[판정] verdict 스키마           ✅  확정 (위 참조)
[판정] llm_analyze.py           ✅  코드/dry-run 검증 (실 LLM 연결은 Colab에서)
[실행] notebooks/colab_llm.ipynb ✅  Ollama+qwen2.5:14b 부팅 노트북
```

## 다음 단계

- [ ] **Colab에서 실 LLM 연결 테스트** (`colab_llm.ipynb`로 verdict 실제 생성·검증)
- [ ] RAG / Vector DB (CVE·IOC 매칭) — `lookup_cve`/`lookup_ioc` 도구 채우기
- [ ] 비콘 탐지 오탐 정리 (NTP/내부 서비스 분리)
- [ ] 대용량 pcap 스트리밍 처리 (현재 compress.py는 전체 메모리 적재)
- [ ] (선택) MAC 제조사(OUI) 조회, DC 역할 자동인식
