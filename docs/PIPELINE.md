# PIPELINE.md — 전체 파이프라인 정비 가이드

> 이 문서 하나로 파이프라인을 이해하고, "어디를 고치면 되는지" 찾을 수 있게 쓴다.
> 코드의 함수/상수 이름 기준으로 설명한다 (줄 번호는 바뀌니 안 씀).

---

## 0. 한눈에 — 데이터 흐름

```
pcap
 ├─(A) run_suricata.sh ─→ output/suricata/<name>/eve.json      (시그니처 alert)
 └─(B) run_zeek.sh    ─→ output/zeek/<name>/*.log              (flow 구조화)
                              │
                  (C) compress.py
                              ├─→ report/<name>.evidence.json      ← LLM이 보는 '요약'
                              └─→ report/<name>.drilldown.json.gz  ← tool이 보는 '원본 부분집합'
                              │
                  (D) llm_analyze.py (+ tools.py)
                              └─→ report/<name>.verdict.json       ← 최종 판정
```

- **A·B·C = 결정론적** (LLM 없음, 같은 입력→같은 출력). GPU 불필요.
- **D = LLM 추론** (Ollama/Qwen). GPU 필요 (Colab).
- 진입점: `scripts/analyze.sh <pcap>` 가 A→B→C 를 순서대로 실행.

### 핵심 불변식 (이거 깨지면 다 틀어짐)
1. **community_id = 조인 키.** Suricata·Zeek 둘 다 seed=0으로 community_id를 켜서, 같은 flow는 양쪽에서 같은 해시. alert↔flow 연결, timeline 앵커링이 전부 이걸로 됨.
2. **output/ 은 git에 안 올라감** (.gitignore). 그래서 Colab엔 원본 로그가 없음 → tool이 읽을 수 있게 `drilldown.json.gz`(원본 부분집합)를 evidence와 같이 커밋한다. **이게 번들이 존재하는 이유.**
3. **stdlib only.** pandas/numpy 안 씀 (Zeek 거친 뒤 데이터가 작아서 불필요 + 의존성 0 = 어디서든 pip 없이 동작).
4. **evidence.json = LLM이 보는 요약 / drilldown.json.gz = tool이 보는 원본.** 둘은 다른 용도.

---

## 1. 수집 단계 (A, B) — `run_suricata.sh`, `run_zeek.sh`

### run_suricata.sh
- 로컬 설치 suricata로 `suricata -r <pcap> -l <out> -k none` 실행.
- `--set outputs.1.eve-log.community-id=true` : community_id 켜기 (조인용).
- `--set ...append=false` + `rm -rf` : 재실행 시 로그 누적 방지.
- 출력: `output/suricata/<name>/eve.json` (이벤트별 JSON 라인).
- **고칠 일**: suricata 옵션/룰 경로. (룰은 시스템 설치분 사용)

### run_zeek.sh  ★포터블★
- **docker ↔ 네이티브 자동 선택**:
  - `command -v zeek` 있으면 → 네이티브 (Colab: docker 없음)
  - 없으면 → `docker run zeek/zeek:latest` (로컬 기본)
- 켜는 정책 스크립트: community-id-logging, mac-logging, hash-all-files, extract-all-files.
- 출력: `output/zeek/<name>/*.log` (conn/http/dns/ssl/files/... JSON) + `extract_files/`.
- **고칠 일**: 새 Zeek 로그/정책 추가는 여기 `ZEEK_SCRIPTS`.

---

## 2. 압축 단계 (C) — `compress.py`  ★제일 자주 고치는 파일★

수십 MB 로그 → ~4.5K 토큰 evidence package. **2층 구조 + 폴백.**

### 흐름 (`build_evidence`가 조립)
```
compress_alerts()   alert 중복제거 + 등급분류(threat/suspicious/info/engine)
compress_conn()     비콘/top-talker/측면이동/포트스캔 + ad_baseline(DC분리)
join_alert_to_flow()  community_id로 alert에 flow 정보 부착
build_timeline()    실제 ts로 공격 흐름 뼈대 (LLM이 시간 못 지어내게)
build_host_profiles()  IP→호스트명/유저/MAC (ntlm/kerberos에서)
REGISTRY[http/dns/files/ssl]  2층 enrichment (전용 압축기)
generic()           등록 안 된 로그는 자동 요약 (안 깨짐)
assess_status()     OK / FAILED_TO_PARSE / NO_IP_FLOWS 판정
```

### 탐지 임계값 (파일 상단 상수 — 여기만 바꾸면 동작 바뀜)
| 상수 | 의미 |
|---|---|
| `BEACON_MIN_CONNS` | 비콘 판정 최소 연결 수 |
| `BEACON_CV_MAX` | 간격 변동계수(CV) 이하면 '규칙적'=비콘 |
| `SCAN_MIN_PORTS` | 포트스캔 판정 포트 수 |
| `LATERAL_PORTS` | 측면이동 감시 포트 (SMB/Kerberos/LDAP/RPC/RDP/WinRM) |
| `DC_BASELINE_PORTS` | DC로 가면 정상 인증으로 칠 포트 (88/389/135/445) |
| `DC_FANIN_MIN` | 내부 N+ 호스트가 Kerberos/LDAP 걸면 그 IP=DC |
| `ALERT_CLASS_RULES` | alert 시그니처 접두사 → 등급 매핑 |
| `NOISE_BUCKET_LIMIT` | info/engine 노이즈 잘라낼 한도 |
| `DRILL_CAPS` | 드릴다운 번들 로그별 상한 |

### DC 오탐 분리 (중요 로직)
- `detect_ad_servers(conn)` : Kerberos(88)/LDAP(389)를 내부 여러 호스트한테 받는 IP = DC.
- `compress_conn`에서 내부→DC 의 AD포트 트래픽은 `lateral_movement`가 아니라 **`ad_baseline`**으로 분리. (클라이언트→DC 인증은 정상)
- 진짜 측면이동 = 내부→**비DC** 관리포트.

### 드릴다운 번들 (`build_drilldown`)
- output/ 전체를 git에 못 올리니, tool이 쓸 부분집합만 추려 `drilldown.json.gz`로 저장.
- 추리는 기준: **외부통신 + 위협 관련 flow + 측면이동 + (DNS는 전부)**. 로그별 `DRILL_CAPS` 상한.
- **고칠 일**: tool이 "데이터 없음"으로 자꾸 실패하면 → 여기 추리는 범위/상한을 넓혀라.

### 자주 하는 수정 → 위치
- **탐지 민감도 조정** → 상단 상수
- **새 탐지기 추가**(예: DNS 터널링) → `compress_conn` 또는 새 함수 + `build_evidence`에 끼우기 + `slim_evidence`(llm_analyze)에 노출
- **새 alert 카테고리** → `ALERT_CLASS_RULES`
- **새 프로토콜 enrichment**(예: smtp 전용) → 함수 작성 후 `REGISTRY`에 등록 (없으면 `generic`이 처리)
- **위협인텔 family 미리 박기**(VirusTotal 결과 등) → `compress_*`에서 sha256/도메인 조회해 `family` 필드 추가 (결정론적 enrichment)

---

## 3. AI 추론 파이프라인 (D) — `llm_analyze.py` + `tools.py`  ★핵심★

### 3-1. 큰 그림
```
evidence.json
  │ slim_evidence()  ← LLM이 실제 보는 것만 추림 (토큰 절약)
  ▼
build_messages() → [system 프롬프트] + [user: slim evidence JSON]
  ▼
run_live() 루프 (최대 max_rounds=8):
   _chat()로 Ollama에 POST → 응답
     ├─ 모델이 tool 호출? → tools.py 실행 → 결과를 대화에 추가 → 다음 라운드
     └─ 모델이 submit_verdict 호출? → enforce_review() → verdict 반환 (끝)
  ▼
verdict.json  (+ tool_trace, rounds_used 기록)
```

### 3-2. 한 '라운드'란
LLM 한 번 호출 = 1라운드. LLM은 한 방에 못 끝내고 "tool 불러줘" 하고 멈춤 → 코드가 실행해 결과 주면 다음 라운드. 이걸 submit_verdict 할 때까지 반복.
- `rounds_used: 1` = tool 안 쓰고 즉답 / `2~5` = 드릴다운하며 확인 / `8`(max) = 헤맴(판정 미제출).

### 3-3. 함수별 역할 (llm_analyze.py)
| 함수/상수 | 역할 | 고칠 일 |
|---|---|---|
| `SYSTEM_PROMPT` | LLM 역할·규칙(환각금지/C2는외부IP만/DC는정상 등) | 판정 행동 바꾸려면 여기 |
| `slim_evidence(ev)` | **LLM이 보는 것 결정** (evidence 중 핵심만) | LLM이 못 보는 정보 있으면 여기 추가 |
| `build_messages(ev)` | system+user 메시지 조립 | |
| `SUBMIT_VERDICT_TOOL` | 판정 출력 **스키마**(구조화 강제) | verdict 필드 바꾸려면 여기 |
| `enforce_review(v)` | `needs_review`를 **코드가 강제**(confidence≠high거나 unknown이면 true) | 검토 정책 |
| `_chat(...)` | Ollama `/v1/chat/completions`로 urllib POST | 엔드포인트/타임아웃 |
| `run_live(...)` | **에이전트 루프**(위 3-1) | 루프/강제정책 |
| `main()` | CLI 인자, `--dry-run`(LLM 없이 배선 점검) | |

- **모델/주소 바꾸기**: CLI `--model` / `--base-url` 또는 env `LLM_MODEL` / `LLM_BASE_URL`. (기본값: qwen2.5:14b, localhost:11434)
- **도구 강제?**: 현재는 강제 안 함(evidence 우선). 빈 tool 결과로 confidence 낮추지 말라고 프롬프트에 명시. (과거 강제는 역효과라 제거함)

### 3-4. 드릴다운 도구 (tools.py)
`DrillDownTools`는 **번들 우선**으로 로드: `report/<name>.drilldown.json.gz` → `.json` → `output/` 폴백.
즉 Colab에선 번들을, 로컬에선 번들 또는 원본 로그를 읽음.

7개 도구 (`TOOL_SCHEMAS`에 스키마 등록, `dispatch`로 라우팅):
| 도구 | 하는 일 |
|---|---|
| `get_flow_detail(community_id)` | 그 flow의 conn/http/dns/ssl/files 묶어서 |
| `search_http(host, uri_contains)` | HTTP 원본 검색 |
| `search_dns(query_contains)` | DNS 쿼리 검색 |
| `search_alerts(signature_contains, src, dst)` | Suricata alert 검색 |
| `get_connections_by_ip(ip)` | IP 관여 flow 전부 |
| `get_malware_file(sha256)` | 파일 메타+추출경로 (※family는 안 줌) |
| `get_host_info(ip/mac)` | 호스트명/유저/MAC 신원 |

- **새 도구 추가**: ① `DrillDownTools`에 메서드 작성 ② `TOOL_SCHEMAS`에 스키마 추가. (`dispatch`는 이름으로 자동 라우팅)
- **위협인텔 도구**(VirusTotal 등)는 여기에 `lookup_file_intel(sha256)` 식으로 추가. 네트워크 API라 Colab에서도 동작(번들 불필요).

---

## 4. "이거 바꾸려면 어디?" 치트시트

| 하고 싶은 것 | 고칠 파일 / 위치 |
|---|---|
| 탐지 민감도(비콘/스캔) | `compress.py` 상단 상수 |
| 새 탐지기 | `compress.py` `compress_conn`/새함수 + `build_evidence` + `slim_evidence` |
| alert 등급 규칙 | `compress.py` `ALERT_CLASS_RULES` |
| 새 프로토콜 요약 | `compress.py` 함수 + `REGISTRY` |
| LLM이 보는 정보 | `llm_analyze.py` `slim_evidence` |
| LLM 행동/규칙 | `llm_analyze.py` `SYSTEM_PROMPT` |
| verdict 출력 필드 | `llm_analyze.py` `SUBMIT_VERDICT_TOOL` + `enforce_review` |
| 새 드릴다운 도구 | `tools.py` 메서드 + `TOOL_SCHEMAS` |
| 위협인텔(VirusTotal) | `tools.py` 새 도구 + (선택)`compress.py` enrichment + 프롬프트 |
| 모델/엔드포인트 | CLI 인자 또는 env (`LLM_MODEL`/`LLM_BASE_URL`) |
| 번들 tool "없음" 실패 | `compress.py` `build_drilldown` 추리 범위/`DRILL_CAPS` |
| Zeek 로그/정책 | `run_zeek.sh` `ZEEK_SCRIPTS` |

---

## 5. 실행 방법

```bash
# 로컬: 수집→압축 (evidence + 번들 생성)
./scripts/analyze.sh pcaps/<file>.pcap

# 개별 단계
bash scripts/run_suricata.sh pcaps/<file>.pcap
bash scripts/run_zeek.sh    pcaps/<file>.pcap
python3 scripts/compress.py <name> --pkts <N> --md

# LLM 판정 (Ollama 떠 있을 때)
python3 scripts/llm_analyze.py <name> \
    --base-url http://localhost:11434/v1 --model qwen2.5:14b

# LLM 없이 배선/토큰만 점검
python3 scripts/llm_analyze.py <name> --dry-run

# 도구 단독 테스트
python3 scripts/tools.py <name>
```

**Colab 올인원**: `notebooks/colab_llm.ipynb` — pcap 업로드 → suricata/zeek 설치 → analyze.sh → llm_analyze.
(Colab엔 docker 없어서 zeek 네이티브 설치. run_zeek.sh가 자동 감지.)

---

## 6. 알려진 한계 / 다음 작업
- **멀웨어 family 어트리뷰션 약함**: 지금은 Suricata 시그니처에 이름 박힌 것만 맞힘(NanoCore O, Qakbot/BazarLoader X). → **위협인텔 도구(VirusTotal sha256→family) 추가 필요.** (tools.py + 프롬프트)
- **암호화(443) C2**: Suricata가 못 봄. JA3 지문/평판으로 잡아야 함(미구현).
- **번들 크기**: gzip으로 ~250KB. pcap 커지면 `DRILL_CAPS` 조정.
- 평가지표(정확도 측정) 자동화 미구현 — 정답(answer.txt) 대비 채점 스크립트가 있으면 좋음.
