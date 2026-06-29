#!/usr/bin/env python3
"""
llm_analyze.py — evidence package를 LLM에 주고 최종 판정(verdict)을 받는다.

설계:
  - OpenAI 호환 API로 통신 → Colab의 Ollama(localhost)든, 나중에 GPU 클라우드든
    base_url만 바꾸면 코드 그대로 동작 (포터블).
  - LLM은 슬림 evidence(요약+타임라인+신원+멀웨어)만 받고, 더 봐야 하면
    tools.py의 드릴다운 도구를 function-calling으로 호출한다.
  - 판정은 submit_verdict 도구 호출로 마무리 → 구조화 출력 강제(자유텍스트 파싱 X).
  - needs_review는 LLM이 아니라 코드가 강제한다.

사용:
  # Colab/서버에서 (Ollama 떠 있을 때)
  python3 llm_analyze.py <name> --base-url http://localhost:11434/v1 --model qwen2.5:14b

  # GPU 없이 프롬프트/배선만 점검 (LLM 호출 안 함)
  python3 llm_analyze.py <name> --dry-run
"""
import argparse
import json
import os

import tools as tools_mod

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SYSTEM_PROMPT = """\
너는 네트워크 보안 분석가다. pcap에서 추출·압축된 evidence package(JSON)를 받아
공격 여부와 정체를 판정한다.

[입력] evidence package는 이미 결정론적으로 압축된 요약이다:
  - ids_alerts: Suricata 시그니처 탐지 (위협/의심만 추림)
  - conn: 비콘(간격 CV)·측면이동·포트스캔 통계
  - host_profiles: IP별 신원(호스트명/유저/MAC)
  - timeline: 실제 타임스탬프 기반 공격 흐름 (네가 시간을 지어내지 말 것)
  - enrichment: http/dns/files(멀웨어 SHA256)

[작업] 다음을 판정한다: 공격 여부 / 멀웨어 패밀리 / C2·공격자·피해자 IP / (해당 시)CVE.

[도구 — 필요시 호출 (evidence 우선)]
  evidence package만으로 확신하면 바로 submit_verdict를 제출하라.
  불확실한 항목이 있을 때만 드릴다운으로 확인하라:
  - beaconing의 C2 정체 불명 → get_flow_detail(community_id)
  - malware_files → get_malware_file(sha256)
  - host_profiles 내부 IP 신원 → get_host_info(ip)
  - http_suspicious → search_http(host)
  ★중요: 드릴다운 결과가 비어 있어도("없음"/0건) evidence에 근거가 있으면 그 근거로 판정하라.
        빈 도구 결과를 이유로 confidence를 낮추거나 공격을 정상(benign)으로 뒤집지 마라.

[환각 방지 — 절대 규칙]
  - CVE: Suricata alert 또는 원본 로그에 CVE 번호가 명시된 경우에만 기재. 없으면 반드시 빈 배열 [].
  - C2: 외부(공인) IP 또는 도메인만. 사설 IP(10./172.16-31./192.168.)·내부 호스트명은 C2가 아니다.
  - 측면이동(Lateral Movement): conn.lateral_movement에 실제로 있는 것만. conn.ad_servers(DC)로의
    Kerberos/LDAP/SMB는 정상 도메인 인증이므로 측면이동·공격으로 보고하지 마라.
  - malware_family: Suricata 시그니처명 또는 get_malware_file로 확인된 것만. 추측으로 채우지 마라.
  - evidence_refs: 실제 존재하는 community_id/sha256/signature만. 지어내지 마라.

[원칙 — 신뢰성 최우선]
  - 환각 금지. 모르면 빈 값으로 두고 confidence를 낮춰라. 억지로 채우지 마라.
  - 모든 판단에 근거(evidence_refs)를 달아라.
  - timeline은 evidence의 timeline을 근거로만 기술하라.
  - 인과("A가 B를 유발")는 단정하지 말고 시간순 관찰로 기술하라.

[종료] 드릴다운을 마친 후 submit_verdict 도구를 호출해 최종 판정을 제출하라.
"""

# 최종 판정 제출용 도구 (구조화 출력 강제 — 자유 텍스트 파싱 안 함)
SUBMIT_VERDICT_TOOL = {
    "type": "function",
    "function": {
        "name": "submit_verdict",
        "description": "최종 분석 판정을 제출한다. 분석을 마쳤을 때 반드시 호출.",
        "parameters": {
            "type": "object",
            "properties": {
                "is_attack": {"type": "boolean"},
                "classification": {"type": "string",
                                   "enum": ["known_threat", "unknown_anomaly", "benign"]},
                "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
                "malware_family": {"type": "string", "description": "없으면 빈 문자열"},
                "cve": {"type": "array", "items": {"type": "string"}},
                "threat_actors": {
                    "type": "object",
                    "properties": {
                        "victim_ips": {"type": "array", "items": {"type": "string"}},
                        "attacker_ips": {"type": "array", "items": {"type": "string"}},
                        "c2": {"type": "array", "items": {
                            "type": "object",
                            "properties": {"ip": {"type": "string"},
                                           "domain": {"type": "string"},
                                           "evidence": {"type": "string"}}}},
                    }},
                "mitre_attack": {"type": "array", "items": {
                    "type": "object",
                    "properties": {"tactic": {"type": "string"},
                                   "technique": {"type": "string"},
                                   "evidence": {"type": "string"}}}},
                "kill_chain_summary": {"type": "string"},
                "reasoning": {"type": "string"},
                "evidence_refs": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["is_attack", "classification", "confidence", "reasoning"],
        },
    },
}


def slim_evidence(ev):
    """LLM에 보낼 핵심만 추림 (토큰 절약). 나머지는 tool로 드릴다운."""
    ids = ev.get("ids_alerts", {})
    threats = [a for a in ids.get("by_signature", [])
               if a.get("bucket") in ("threat", "suspicious")]
    conn = ev.get("conn", {})
    enr = ev.get("enrichment", {})
    return {
        "meta": ev.get("meta", {}),
        "ids_alerts": {"bucket_counts": ids.get("bucket_counts", {}),
                       "threats": threats},
        "conn": {"beaconing": conn.get("beaconing", []),
                 "lateral_movement": conn.get("lateral_movement", []),
                 "port_scans": conn.get("port_scans", []),
                 # DC(ad_servers)로의 Kerberos/LDAP/SMB는 정상 인증 → 측면이동 아님(요약만 전달)
                 "ad_servers": conn.get("ad_servers", []),
                 "ad_baseline_count": conn.get("ad_baseline_count", 0),
                 "top_talkers_external": conn.get("top_talkers_external", [])[:5]},
        "host_profiles": ev.get("host_profiles", {}),
        "timeline": ev.get("timeline", []),
        "malware_files": enr.get("files", {}).get("malware_candidates", []),
        "http_suspicious": enr.get("http", {}).get("suspicious", [])[:10],
        "dns_suspicious": enr.get("dns", {}).get("suspicious", [])[:10],
    }


def build_messages(ev):
    slim = slim_evidence(ev)
    user = ("아래 evidence package를 분석하고 submit_verdict로 판정을 제출하라.\n\n"
            "```json\n" + json.dumps(slim, ensure_ascii=False) + "\n```")
    return [{"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user}]


# 이 접두사 시그니처가 떴으면 '알려진 악성'이 결정론적 사실 → LLM이 benign으로 못 뒤집음
HARD_MALWARE_PREFIXES = ("ET MALWARE", "ETPRO MALWARE", "ET TROJAN", "ET CNC")


def _evidence_threat_floor(ev):
    """evidence에서 결정론적으로 확실한 위협 신호 추출 (LLM 판단과 무관한 사실)."""
    ids = ev.get("ids_alerts", {})
    threat = [a for a in ids.get("by_signature", []) if a.get("bucket") == "threat"]
    hard = [a["signature"] for a in threat
            if any((a.get("signature") or "").startswith(p) for p in HARD_MALWARE_PREFIXES)]
    return {"threat_sigs": [a["signature"] for a in threat], "hard_malware": hard}


def enforce_review(verdict, ev=None):
    """코드가 강제하는 후처리 — LLM 판단에 맡기지 않는다.
       1) needs_review: confidence≠high 또는 unknown_anomaly면 사람 검토.
       2) 가드레일: 위협 시그니처(ET MALWARE 등)는 결정론적 사실 → benign 불가."""
    conf = verdict.get("confidence")
    cls = verdict.get("classification")
    verdict["needs_review"] = (conf != "high") or (cls == "unknown_anomaly")

    if ev is not None:
        floor = _evidence_threat_floor(ev)
        # ET MALWARE/TROJAN/CNC가 떴는데 LLM이 benign/공격아님이라 하면 강제 정정
        if floor["hard_malware"] and (cls == "benign" or verdict.get("is_attack") is False):
            verdict["is_attack"] = True
            verdict["classification"] = "known_threat"
            verdict["needs_review"] = True
            verdict.setdefault("rule_overrides", []).append(
                "악성 시그니처 탐지로 benign 차단: " + ", ".join(floor["hard_malware"][:5]))
        # 위협 시그니처가 있는데 benign이면(하드 아님이라도) 최소 검토 강제
        elif floor["threat_sigs"] and cls == "benign":
            verdict["needs_review"] = True
            verdict.setdefault("rule_overrides", []).append(
                "위협 시그니처 존재로 검토 필요: " + ", ".join(floor["threat_sigs"][:5]))
    return verdict


def p(*a):
    """flush 강제 — Colab/노트북에서 진행상황이 실시간으로 흐르게."""
    print(*a, flush=True)


def _preview(obj, n=200):
    """tool 인자/결과를 한 줄로 줄여 미리보기 (공백 정리 + 길이 제한)."""
    s = obj if isinstance(obj, str) else json.dumps(obj, ensure_ascii=False)
    s = " ".join(s.split())
    return s[:n] + ("…" if len(s) > n else "")


def _chat(base_url, api_key, model, messages, tools, temperature):
    import urllib.request
    url = base_url.rstrip("/") + "/chat/completions"
    body = json.dumps({
        "model": model,
        "messages": messages,
        "tools": tools,
        "tool_choice": "auto",
        "temperature": temperature,
    }).encode()
    req = urllib.request.Request(url, data=body, headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    })
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())


def run_live(name, ev, base_url, api_key, model, max_rounds, temperature):
    drill = tools_mod.DrillDownTools(name)
    all_tools = tools_mod.TOOL_SCHEMAS + [SUBMIT_VERDICT_TOOL]
    messages = build_messages(ev)
    trace = []   # tool 호출 기록 → verdict에 저장(사후 측정용)

    p(f"\n{'=' * 60}")
    p(f"  LLM 분석 시작: {name}")
    p(f"  model={model}  max_rounds={max_rounds}  tools={len(tools_mod.TOOL_SCHEMAS)}개")
    p(f"{'=' * 60}")

    for r in range(max_rounds):
        p(f"\n── round {r} " + "─" * 40)
        resp = _chat(base_url, api_key, model, messages, all_tools, temperature)
        msg = resp["choices"][0]["message"]
        messages.append({k: v for k, v in msg.items() if v is not None})

        # 모델이 내놓은 텍스트(추론/진행 설명)가 있으면 표시
        content = msg.get("content") or ""
        if content.strip():
            p(f"  💭 {_preview(content, 400)}")

        tool_calls = msg.get("tool_calls") or []
        if not tool_calls:
            p("  ⚠️  tool 호출 없음 → submit_verdict 유도")
            messages.append({"role": "user",
                             "content": "분석을 마쳤으면 submit_verdict 도구로 판정을 제출하라. "
                                        "evidence에 근거가 있으면 추가 도구 없이 바로 제출해도 된다."})
            continue

        for tc in tool_calls:
            fn = tc["function"]["name"]
            try:
                args = json.loads(tc["function"].get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {}

            if fn == "submit_verdict":
                p("  ✅ submit_verdict 호출 — 최종 판정 제출")
                verdict = enforce_review(args, ev)
                verdict["tool_trace"] = trace
                verdict["rounds_used"] = r + 1
                return verdict

            # 드릴다운 도구 실행
            result = tools_mod.dispatch(drill, fn, args)
            size = len(json.dumps(result, ensure_ascii=False))
            trace.append({"round": r, "tool": fn, "args": args, "result_size": size})
            p(f"  🔧 {fn}({_preview(args, 120)})")
            p(f"      → ({size}자) {_preview(result, 220)}")
            messages.append({"role": "tool", "tool_call_id": tc["id"],
                             "content": json.dumps(result, ensure_ascii=False)})

    p("\n  ❌ max_rounds 초과 — 판정 미제출")
    return {"error": "max_rounds 초과 — 판정 미제출", "needs_review": True,
            "tool_trace": trace, "rounds_used": max_rounds}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("name")
    ap.add_argument("--base-url", default=os.environ.get("LLM_BASE_URL", "http://localhost:11434/v1"))
    ap.add_argument("--api-key", default=os.environ.get("LLM_API_KEY", "EMPTY"))
    ap.add_argument("--model", default=os.environ.get("LLM_MODEL", "qwen2.5:14b"))
    ap.add_argument("--max-rounds", type=int, default=8)
    ap.add_argument("--temperature", type=float, default=0.0)
    ap.add_argument("--dry-run", action="store_true", help="LLM 호출 없이 프롬프트/배선만 점검")
    args = ap.parse_args()

    ev_path = os.path.join(ROOT, "report", f"{args.name}.evidence.json")
    if not os.path.exists(ev_path):
        raise SystemExit(f"[!] evidence 없음: {ev_path} (먼저 analyze.sh 실행)")
    ev = json.load(open(ev_path, encoding="utf-8"))

    if args.dry_run:
        msgs = build_messages(ev)
        slim_len = len(msgs[1]["content"])
        print(f"=== DRY RUN: {args.name} ===")
        print(f"system prompt: {len(SYSTEM_PROMPT)}자")
        print(f"슬림 evidence: {slim_len}자 (~{slim_len // 3} 토큰 추정, 원본 대비 축소)")
        print(f"등록 도구: {[t['function']['name'] for t in tools_mod.TOOL_SCHEMAS] + ['submit_verdict']}")
        print("\n--- user 메시지 미리보기(앞 800자) ---")
        print(msgs[1]["content"][:800])
        return

    verdict = run_live(args.name, ev, args.base_url, args.api_key,
                       args.model, args.max_rounds, args.temperature)
    out = os.path.join(ROOT, "report", f"{args.name}.verdict.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(verdict, f, ensure_ascii=False, indent=2)

    # tool 사용 요약 — "진짜 드릴다운 했나"를 한눈에 (verdict.json에도 tool_trace로 저장됨)
    from collections import Counter
    trace = verdict.get("tool_trace", [])
    p(f"\n{'=' * 60}")
    if trace:
        c = Counter(t["tool"] for t in trace)
        p(f"[tool 사용] 총 {len(trace)}회 / {verdict.get('rounds_used','?')}라운드")
        for tool, n in c.most_common():
            p(f"   - {tool}: {n}회")
    else:
        p(f"[tool 사용] 0회 ❌ — 모델이 evidence만으로 판정 (드릴다운 안 함, {verdict.get('rounds_used','?')}라운드)")
    p(f"{'=' * 60}")

    p(f"\n[+] verdict -> {out}")
    p(json.dumps(verdict, ensure_ascii=False, indent=2)[:600])


if __name__ == "__main__":
    main()
