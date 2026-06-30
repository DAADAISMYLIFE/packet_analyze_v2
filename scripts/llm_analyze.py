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
  python3 llm_analyze.py <name> --base-url http://localhost:11434/v1 --model gemma4:26b

  # GPU 없이 프롬프트/배선만 점검 (LLM 호출 안 함)
  python3 llm_analyze.py <name> --dry-run
"""
import argparse
import json
import os

import tools as tools_mod

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SYSTEM_PROMPT = """\
You are a network security analyst. You receive an evidence package (JSON) that was
deterministically extracted and compressed from a pcap, and you decide whether an attack
occurred and what it is.

[INPUT] The evidence package is an already-compressed, deterministic summary:
  - ids_alerts: Suricata signature detections (threats / suspicious only)
  - conn: beaconing (inter-arrival CV), lateral movement, port-scan statistics
  - host_profiles: per-IP identity (hostname / user / MAC)
  - timeline: attack flow anchored to real timestamps (do NOT invent times)
  - enrichment: http / dns / files (malware SHA256)

[TASK] Decide: is it an attack / malware family / C2 / attacker & victim hosts / CVE (if any).

[METHOD — evidence is the starting point; confirm and expand with tools]
  The evidence package is a set of LEADS, not conclusions. Do not turn a lead directly into
  a verdict; drill into each lead with tools, gather the related facts, then decide on
  complete grounds.
  - a threat signature / beacon pointing at a C2 → get_flow_detail(community_id) +
    get_connections_by_ip(ip) to inspect the actual traffic and related IPs
  - a sha256 in malware_files → get_malware_file to confirm the file
  - a related internal host → get_host_info(ip) to confirm the victim identity
  - a suspicious domain / URI → search_http / search_dns to check the path
  KEY: the MORE confident a lead makes you, the more you must verify and expand it with
  tools. Confidence is a signal to dig deeper, not a license to skip investigation.
  If a drill-down comes back empty ("none" / 0 results) but the evidence still supports the
  finding, decide on that evidence — do NOT lower confidence or flip to benign for that reason.

[IDENTIFY THE ACTORS — IP is not enough]
  For every victim and attacker, report not just the IP but also the hostname and username
  when they can be found. Pull them from host_profiles (hostname / user) for that IP, or via
  get_host_info(ip). If a hostname or username is genuinely unknown, leave it as an empty
  string — never guess it.

[HALLUCINATION PREVENTION — hard rules]
  - CVE: include a CVE number ONLY if it appears explicitly in a Suricata alert or the raw
    logs. Otherwise the array MUST be empty [].
  - C2: external (public) IPs or domains only. Private IPs (10./172.16-31./192.168.) and
    internal hostnames are NEVER C2.
  - Lateral movement: only what actually appears in conn.lateral_movement. Kerberos / LDAP /
    SMB toward conn.ad_servers (Domain Controllers) is normal domain authentication — do NOT
    report it as lateral movement or as an attack.
  - malware_family: only what a Suricata signature names or get_malware_file confirms. Never
    fill it in by guessing.
  - evidence_refs: only community_id / sha256 / signature values that actually exist. Never
    invent them.

[DETERMINISTIC THREAT FLOOR — this overrides your own judgment]
  If a hard-malware signature is present (its name starts with "ET MALWARE", "ETPRO MALWARE",
  "ET TROJAN", or "ET CNC"), that is an established fact: is_attack MUST be true and
  classification MUST be "known_threat". You may NOT return benign in that case. More
  generally, if ANY threat-bucket signature is present, do not return benign.

[PRINCIPLES — reliability first]
  - No hallucination. If unknown, leave the value empty and lower confidence. Do not force-fill.
  - Attach grounds (evidence_refs) to every conclusion.
  - Describe the timeline only from the evidence timeline.
  - Do not assert causation ("A caused B"); describe chronological observation instead.

[OUTPUT LANGUAGE] Write every free-text field — reasoning, kill_chain_summary, and any
  evidence text — in Korean (한국어). Keep identifiers verbatim (IPs, hostnames, usernames,
  signatures, hashes, CVE IDs, MITRE technique IDs).

[EXAMPLE — shape of a good verdict; use the REAL evidence, this is only the form]
  submit_verdict({
    "is_attack": true,
    "classification": "known_threat",
    "confidence": "high",
    "malware_family": "TrickBot",
    "cve": [],
    "threat_actors": {
      "victims": [{"ip": "10.0.0.15", "hostname": "FIN-PC03", "username": "j.doe",
                   "evidence": "ET MALWARE TrickBot CnC Checkin 출발 호스트"}],
      "attackers": [],
      "c2": [{"ip": "203.0.113.7", "domain": "",
              "evidence": "ET MALWARE TrickBot CnC Checkin"}]
    },
    "mitre_attack": [
      {"tactic": "Command and Control", "technique": "T1071.001",
       "evidence": "203.0.113.7로 주기적 HTTP 비콘 (CV 0.04, 120건)"}
    ],
    "kill_chain_summary": "FIN-PC03(10.0.0.15, j.doe)가 203.0.113.7로 TrickBot CnC 체크인 비콘을 반복",
    "reasoning": "ET MALWARE 시그니처와 낮은 CV의 주기적 비콘이 일치. get_flow_detail로 C2 통신, get_host_info로 피해자 신원 확인.",
    "evidence_refs": ["1:abcd1234...", "ET MALWARE TrickBot CnC Checkin"]
  })

[FINISH] After drilling down, call the submit_verdict tool to submit your final verdict.
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
                        # victim/attacker는 IP만이 아니라 hostname/username까지 함께 (모르면 빈 문자열)
                        "victims": {"type": "array", "items": {
                            "type": "object",
                            "properties": {"ip": {"type": "string"},
                                           "hostname": {"type": "string", "description": "없으면 빈 문자열"},
                                           "username": {"type": "string", "description": "없으면 빈 문자열"},
                                           "evidence": {"type": "string"}}}},
                        "attackers": {"type": "array", "items": {
                            "type": "object",
                            "properties": {"ip": {"type": "string"},
                                           "hostname": {"type": "string", "description": "없으면 빈 문자열"},
                                           "username": {"type": "string", "description": "없으면 빈 문자열"},
                                           "evidence": {"type": "string"}}}},
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
    user = ("Analyze the evidence package below and submit your verdict via submit_verdict.\n\n"
            "```json\n" + json.dumps(slim, ensure_ascii=False) + "\n```")
    return [{"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user}]


# 이 접두사 시그니처가 떴으면 '알려진 악성'이 결정론적 사실 → LLM이 benign으로 못 뒤집음
HARD_MALWARE_PREFIXES = ("ET MALWARE", "ETPRO MALWARE", "ET TROJAN", "ET CNC")


def _is_private(ip):
    import ipaddress
    try:
        return ipaddress.ip_address(ip).is_private
    except (ValueError, TypeError):
        return False


def _evidence_threat_floor(ev):
    """evidence에서 결정론적으로 확실한 위협 신호 추출 (LLM 판단과 무관한 사실)."""
    ids = ev.get("ids_alerts", {})
    threat = [a for a in ids.get("by_signature", []) if a.get("bucket") == "threat"]
    hard = [a["signature"] for a in threat
            if any((a.get("signature") or "").startswith(p) for p in HARD_MALWARE_PREFIXES)]
    return {"threat_sigs": [a["signature"] for a in threat], "hard_malware": hard}


def _host_identity(ev, ip):
    """host_profiles에서 ip의 hostname/username을 결정론적으로 조회 (없으면 빈 문자열)."""
    prof = ev.get("host_profiles", {}).get(ip, {}) or {}
    return prof.get("hostname") or "", prof.get("user") or ""


def _derive_iocs(ev):
    """위협 alert에서 C2/victim을 결정론적으로 추출.
       외부(공인) dst = C2 후보, 내부 src = 피해자. LLM이 빼먹어도 코드가 보장한다.
       victim은 host_profiles로 hostname/username까지 채운다."""
    victims, c2 = {}, {}
    for a in ev.get("ids_alerts", {}).get("by_signature", []):
        if a.get("bucket") != "threat":
            continue
        sig = a.get("signature")
        for s in a.get("src_ips", []):
            if _is_private(s) and s not in victims:
                host, user = _host_identity(ev, s)
                victims[s] = {"ip": s, "hostname": host, "username": user,
                              "evidence": f"위협 시그니처 출발 호스트: {sig}"}
        for d in a.get("dst_ips", []):
            if d and not _is_private(d):
                c2.setdefault(d, sig)  # 첫 시그니처를 근거로
    return victims, c2


def _merge_actor(existing, derived):
    """모델이 낸 actor 객체에 결정론적 신원을 보강 (모델 값 우선, 빈 칸만 채움)."""
    out = dict(existing) if isinstance(existing, dict) else {"ip": existing}
    for k in ("hostname", "username", "evidence"):
        if not out.get(k) and derived.get(k):
            out[k] = derived[k]
    return out


def _backfill_iocs(verdict, ev):
    """verdict.threat_actors에 결정론적 C2/victim을 합집합으로 백필 (모델 누락 보완)."""
    victims, c2 = _derive_iocs(ev)
    if not victims and not c2:
        return
    ta = verdict.setdefault("threat_actors", {})

    # victim 합집합 (ip 기준 중복 제거, 모델 값에 신원 보강)
    by_ip = {}
    for v in (ta.get("victims") or []):
        ip = v.get("ip") if isinstance(v, dict) else v
        if ip:
            by_ip[ip] = _merge_actor(v, victims.get(ip, {}))
    for ip, dv in victims.items():
        by_ip[ip] = _merge_actor(by_ip.get(ip, dv), dv)
    ta["victims"] = [by_ip[ip] for ip in sorted(by_ip)]

    # c2 합집합 (ip 기준 중복 제거)
    have = {c.get("ip") for c in (ta.get("c2") or []) if isinstance(c, dict) and c.get("ip")}
    merged = list(ta.get("c2") or [])
    added = []
    for ip, sig in sorted(c2.items()):
        if ip not in have:
            merged.append({"ip": ip, "domain": "", "evidence": f"위협 시그니처: {sig}"})
            added.append(ip)
    ta["c2"] = merged
    if added:
        verdict.setdefault("rule_overrides", []).append(
            "C2 결정론적 백필(위협 alert 외부 dst): " + ", ".join(added))


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
        # 공격 판정이면 C2/victim을 결정론적으로 백필 (모델이 빼먹어도 IOC 보장)
        if verdict.get("is_attack"):
            _backfill_iocs(verdict, ev)
    return verdict


def p(*a):
    """flush 강제 — Colab/노트북에서 진행상황이 실시간으로 흐르게."""
    print(*a, flush=True)


def _preview(obj, n=200):
    """tool 인자/결과를 한 줄로 줄여 미리보기 (공백 정리 + 길이 제한)."""
    s = obj if isinstance(obj, str) else json.dumps(obj, ensure_ascii=False)
    s = " ".join(s.split())
    return s[:n] + ("…" if len(s) > n else "")


def _chat(base_url, api_key, model, messages, tools, temperature, tool_choice="required"):
    import urllib.request
    url = base_url.rstrip("/") + "/chat/completions"
    body = json.dumps({
        "model": model,
        "messages": messages,
        "tools": tools,
        # required = 매 턴 도구 호출 강제 → 모델이 산문으로 새는 것 차단
        # (auto면 evidence에 답이 다 있을 때 도구 안 부르고 텍스트로 답해버림)
        "tool_choice": tool_choice,
        "temperature": temperature,
    }).encode()
    req = urllib.request.Request(url, data=body, headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    })
    # timeout: 26B 모델은 1턴이 수 분 걸릴 수 있어 넉넉히. 무한 대기로 라운드 전체가
    # 멈추는 것만 방지 (정확성 우선이라 짧게 끊어 답을 자르지 않는다).
    with urllib.request.urlopen(req, timeout=900) as r:
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
                             "content": "If you are done analyzing, submit your verdict via the "
                                        "submit_verdict tool. If the evidence already supports a "
                                        "finding, submit directly without further tool calls."})
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
    ap.add_argument("--model", default=os.environ.get("LLM_MODEL", "gemma4:26b"))
    ap.add_argument("--max-rounds", type=int, default=8)
    ap.add_argument("--temperature", type=float, default=0.0)
    ap.add_argument("--dry-run", action="store_true", help="LLM 호출 없이 프롬프트/배선만 점검")
    args = ap.parse_args()

    ev_path = os.path.join(ROOT, "report", f"{args.name}.evidence.json")
    if not os.path.exists(ev_path):
        raise SystemExit(f"[!] evidence 없음: {ev_path} (먼저 analyze.sh 실행)")
    with open(ev_path, encoding="utf-8") as f:
        ev = json.load(f)

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

    # 입력이 깨졌으면(파싱 실패/비IP) LLM에 물어보지 않는다 — 빈 evidence에 대고
    # "benign/위협없음" 같은 오판을 내는 걸 차단(meta.status의 존재 이유).
    status = ev.get("meta", {}).get("status", "OK")
    if status != "OK":
        verdict = {
            "status": status,
            "is_attack": False,
            "classification": "unknown_anomaly",
            "confidence": "low",
            "needs_review": True,
            "reasoning": (f"입력 분석 실패(status={status}). "
                          f"evidence가 비어 LLM 판정을 생략했다. 경고: "
                          + "; ".join(ev.get("meta", {}).get("warnings", []))),
            "rounds_used": 0,
            "tool_trace": [],
        }
        p(f"[!] status={status} — LLM 판정 생략, needs_review로 표시")
    else:
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
