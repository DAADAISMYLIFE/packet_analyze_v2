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
import re

import tools as tools_mod
from compress import LATERAL_PORTS  # victim 내부이동 판정에 재사용 (단일 출처)

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

[PRE-VERIFIED FACTS — 이미 확인된 사실]
  The user message includes a PRE-VERIFIED FACTS block: drill-down results the code already
  ran for you (malware files, threat/beacon flows, victim identity & internal connections,
  suspicious DNS/HTTP). Treat these as PRIMARY ground truth.
  - Where a field says "없음 / 0건 / none", judge by that — do NOT fill it with guesses.
  - Report lateral movement ONLY if a victim's internal_admin_targets is non-empty.
  - Identify malware family from the verified malware_files / flow contents, not from guessing.

[KILL CHAIN — 인과는 timeline 순서로만 판단]
  - Use timeline timestamps to order events. An event that happens AFTER a host is already
    infected CANNOT be that host's infection vector.
  - Hosts that each contact DIFFERENT external C2 / download DIFFERENT malware families are
    INDEPENDENT infections. Do NOT merge them into one host "spreading" to the others.
  - Host→host lateral movement (admin ports / SVCCTL) timestamped AFTER the targets are already
    infected is POST-COMPROMISE activity, NOT how they got infected.
  - If the initial access vector (e.g., a phishing email) is NOT in the capture, do not invent it.
    Describe the EARLIEST OBSERVED malicious activity per host instead.
  - Structure kill_chain_summary per host — (infection time / malware family / C2) — and report
    lateral movement as a separate, later stage if present.

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

[HYPOTHESES — 미지 영역은 '추론'하되 사실과 분리하라]
  요약·나열로 끝내지 마라. 정황이 없어 evidence로 직접 답할 수 없는 핵심 질문
  (초기 침투 벡터, 공격자 정체·의도, 데이터가 있었다면 도구가 무엇을 보여줬을지 등)은
  '명시적 가설'로 추론하라 — 단, 절대 사실인 척하지 마라.
  - 각 가설마다: hypothesis(가설), supports[](뒷받침 근거), contradicts[](반하는 근거),
    confidence, how_to_confirm(무엇이 있으면 확증/반증되나)를 채워라.
  - 관측된 패턴에서 추론하라. 예: "여러 호스트가 거의 동시에, 선행 익스플로잇/스캔 없이,
    서로 다른 커모디티 멀웨어에 독립 감염 → 외부 전달(피싱 이메일 등)일 가능성" (확정 아님).
  - 사실 필드(is_attack/malware_family/c2/victims/mitre)는 엄격히 grounded로 유지하고,
    추론적 도약은 오직 hypotheses에만 담아라. 가설을 사실로 승격하지 마라.

[OUTPUT LANGUAGE] Write every free-text field — reasoning, kill_chain_summary, hypotheses, and
  any evidence text — in Korean (한국어). Keep identifiers verbatim (IPs, hostnames, usernames,
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
    "evidence_refs": ["1:abcd1234...", "ET MALWARE TrickBot CnC Checkin"],
    "hypotheses": [
      {"hypothesis": "초기 침투는 피싱 이메일 첨부 가능성 (캡처에 메일 없음)",
       "supports": ["선행 익스플로잇/스캔 트래픽 없음", "TrickBot은 통상 악성 첨부로 전달"],
       "contradicts": ["캡처에 수신 SMTP/이메일 부재로 직접 확인 불가"],
       "confidence": "low",
       "how_to_confirm": "메일 게이트웨이 로그 또는 수신 SMTP 캡처 확보"}
    ]
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
                # 미지 영역에 대한 추론 — 사실과 분리. supports/contradicts로 근거 가중, 사실로 승격 금지
                "hypotheses": {"type": "array", "items": {
                    "type": "object",
                    "properties": {
                        "hypothesis": {"type": "string"},
                        "supports": {"type": "array", "items": {"type": "string"}},
                        "contradicts": {"type": "array", "items": {"type": "string"}},
                        "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
                        "how_to_confirm": {"type": "string"}}}},
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


def build_messages(ev, preinvest=None):
    slim = slim_evidence(ev)
    parts = ["Analyze the evidence package below and submit your verdict via submit_verdict.",
             "", "```json", json.dumps(slim, ensure_ascii=False), "```"]
    if preinvest:
        parts += ["",
                  "[PRE-VERIFIED FACTS] 코드가 드릴다운으로 이미 확인한 사실이다. 1차 근거로 삼아라. "
                  "'없음/0건'인 항목은 추측으로 채우지 말 것.",
                  "```json", json.dumps(preinvest, ensure_ascii=False), "```"]
    return [{"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": "\n".join(parts)}]


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
        _strip_unfounded(verdict, ev)
    return verdict


def _strip_unfounded(verdict, ev):
    """evidence로 검증 가능한 환각만 결정론적으로 제거 (사건유형 무관 일반 가드).
       - 측면이동 주장: conn.lateral_movement가 비어 있으면 해당 MITRE 항목 제거
       - CVE: 어떤 시그니처에도 없는 CVE는 제거 (프롬프트 규칙을 코드로 승격)."""
    # 1) 측면이동 무근거 제거
    if not ev.get("conn", {}).get("lateral_movement"):
        mitre = verdict.get("mitre_attack")
        if isinstance(mitre, list):
            kept = [m for m in mitre if isinstance(m, dict) and
                    "lateral" not in (str(m.get("tactic", "")) + str(m.get("technique", ""))).lower()]
            if len(kept) != len(mitre):
                verdict["mitre_attack"] = kept
                verdict.setdefault("rule_overrides", []).append(
                    "측면이동 근거(conn.lateral_movement) 없음 → 해당 MITRE 제거")
    # 2) 근거 없는 CVE 제거
    cves = verdict.get("cve")
    if isinstance(cves, list) and cves:
        sigs = " ".join(str(a.get("signature") or "")
                        for a in ev.get("ids_alerts", {}).get("by_signature", []))
        present = {c.upper() for c in re.findall(r"CVE-\d{4}-\d+", sigs, re.I)}
        bad = [c for c in cves if isinstance(c, str) and c.upper() not in present]
        if bad:
            verdict["cve"] = [c for c in cves if c not in bad]
            verdict.setdefault("rule_overrides", []).append("근거 없는 CVE 제거: " + ", ".join(bad))


def p(*a):
    """flush 강제 — Colab/노트북에서 진행상황이 실시간으로 흐르게."""
    print(*a, flush=True)


def _preview(obj, n=200):
    """tool 인자/결과를 한 줄로 줄여 미리보기 (공백 정리 + 길이 제한)."""
    s = obj if isinstance(obj, str) else json.dumps(obj, ensure_ascii=False)
    s = " ".join(s.split())
    return s[:n] + ("…" if len(s) > n else "")


def _first_json_object(text):
    """문자열에서 첫 번째 균형잡힌 {...} 블록을 추출 (문자열 내부의 중괄호는 무시)."""
    start = text.find("{")
    if start < 0:
        return None
    depth, in_str, esc = 0, False, False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return None  # 닫히지 않음 (출력 잘림 등)


def _salvage_json(text):
    """잘린 JSON 복구 — 출력이 토큰 한도 등으로 중간에 끊겨도 앞부분 필드는 살린다.
       (is_attack/classification는 앞쪽이라 보통 살아남음 → round 0 결과를 안 버리려고)."""
    start = text.find("{")
    if start < 0:
        return None
    stack, in_str, esc = [], False, False
    for ch in text[start:]:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch in "{[":
            stack.append(ch)
        elif ch in "}]":
            if stack:
                stack.pop()
    frag = text[start:]
    if in_str:                       # 문자열 도중에 끊김 → 닫아줌
        frag += '"'
    frag = frag.rstrip()
    frag = re.sub(r'[,:]\s*$', '', frag)        # 끝의 dangling 콤마/콜론 제거
    frag = re.sub(r',\s*("(?:[^"\\]|\\.)*")?\s*$', '', frag)  # 끝의 미완성 키 제거
    for opener in reversed(stack):   # 안 닫힌 괄호 보충
        frag += "}" if opener == "{" else "]"
    try:
        return json.loads(frag)
    except (json.JSONDecodeError, ValueError):
        return None


def _extract_verdict(text):
    """모델이 tool_call 대신 content에 텍스트로 낸 verdict JSON을 파싱.
       gemma4 등 Ollama가 tool_choice=required를 강제 안 해 본문으로 답할 때의 폴백.
       ```json 블록 → 균형 스캔 → 잘림 복구 순으로 최대한 살린다."""
    if not text:
        return None
    cands = []
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)  # ```json 블록 우선
    if m:
        cands.append(m.group(1))
    cands.append(_first_json_object(text))  # 펜스 없으면 균형 스캔
    cands.append(_salvage_json(text))       # 그래도 안 되면 잘림 복구
    for c in cands:
        if not c:
            continue
        obj = c if isinstance(c, dict) else None
        if obj is None:
            try:
                obj = json.loads(c)
            except (json.JSONDecodeError, ValueError):
                continue
        if isinstance(obj, dict) and ("classification" in obj or "is_attack" in obj):
            return obj
    return None


def _chat(base_url, api_key, model, messages, tools, temperature, tool_choice="required"):
    import urllib.request
    url = base_url.rstrip("/") + "/chat/completions"
    body = json.dumps({
        "model": model,
        "messages": messages,
        "tools": tools,
        # NOTE: Ollama는 tool_choice="required"를 강제하지 않을 때가 많다(auto처럼 동작).
        # 그래서 강제에 의존하지 않고, content로 새어 나온 verdict는 run_live가 파싱해서 채택한다.
        "tool_choice": tool_choice,
        "temperature": temperature,
        # verdict JSON이 토큰 한도로 잘려 파싱 실패하는 것 방지 (정확성 우선, 넉넉히)
        "max_tokens": 8192,
    }).encode()
    req = urllib.request.Request(url, data=body, headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    })
    # timeout: 26B 모델은 1턴이 수 분 걸릴 수 있어 넉넉히. 무한 대기로 라운드 전체가
    # 멈추는 것만 방지 (정확성 우선이라 짧게 끊어 답을 자르지 않는다).
    with urllib.request.urlopen(req, timeout=900) as r:
        return json.loads(r.read())


# ── 강제 사전조사(mandatory pre-investigation) ──────────────────────────
# 모델 의지에 안 맡기고, evidence에 '있는 신호'만 보고 코드가 필수 드릴다운을 먼저 돌린다.
# 사건유형(악성코드/스캔/유출/웹공격…)에 하드코딩하지 않음 — 신호 있으면 조사, 없으면 스킵.
PREINVEST_CAPS = {"total": 24, "malware": 6, "flows": 6, "victims": 5, "dns": 5, "http": 5}


def _sum_flow(r):
    """get_flow_detail 결과를 토큰 절약용으로 압축 (원본 배열 통째로 안 넣음)."""
    if not isinstance(r, dict) or r.get("error"):
        return r
    c = (r.get("conn") or [{}])[0]
    return {
        "community_id": r.get("community_id"),
        "conn": {k: c.get(k) for k in ("id.orig_h", "id.resp_h", "id.resp_p",
                                       "proto", "service", "orig_bytes", "resp_bytes", "conn_state")},
        "http": [{"host": h.get("host"), "uri": (h.get("uri") or "")[:80],
                  "method": h.get("method"), "status": h.get("status_code"),
                  "mime": h.get("resp_mime_types")} for h in (r.get("http") or [])[:5]],
        "dns": [d.get("query") for d in (r.get("dns") or [])[:5]],
        "files": [{"sha256": f.get("sha256"), "mime": f.get("mime_type")}
                  for f in (r.get("files") or [])[:5]],
    }


def _sum_search(r, fields, n=5):
    """search_http/search_dns 결과 압축: matched 수 + 상위 일부 레코드."""
    if not isinstance(r, dict):
        return r
    recs = r.get("records") or []
    return {"matched": r.get("matched", len(recs)),
            "sample": [{k: rec.get(k) for k in fields if rec.get(k) is not None}
                       for rec in recs[:n]]}


def essential_investigation(ev, drill, trace):
    """evidence 신호 → 필수 드릴다운을 결정론적으로 강제 실행.
       hit과 negative('확인했으나 없음')를 함께 반환해 모델 추측을 억제한다. 전역 예산으로 상한."""
    caps = PREINVEST_CAPS
    budget = [caps["total"]]

    def run(tool, fn, **args):
        if budget[0] <= 0:
            return None
        budget[0] -= 1
        res = fn(**args)
        trace.append({"round": -1, "tool": tool, "args": args,
                      "result_size": len(json.dumps(res, ensure_ascii=False))})
        return res

    out = {}

    # 1) 멀웨어 파일 확정 (sha256 있을 때만)
    mals = ev.get("enrichment", {}).get("files", {}).get("malware_candidates", [])
    fres = []
    for m in mals[:caps["malware"]]:
        if m.get("sha256"):
            r = run("get_malware_file", drill.get_malware_file, sha256=m["sha256"])
            if r is not None:
                fres.append({k: r.get(k) for k in
                             ("sha256", "md5", "mime_type", "seen_bytes", "download_count")}
                            if isinstance(r, dict) and not r.get("error") else r)
    out["malware_files"] = fres or {"checked": 0, "note": "악성 파일 후보 없음"}

    # 2) 위협/비콘 flow 상세 (C2 실체 vs 다운로드 소스 구분 등)
    cids, seen, flows = [], set(), []
    for a in ev.get("ids_alerts", {}).get("by_flow", []):
        if a.get("community_id"):
            cids.append(a["community_id"])
    for b in ev.get("conn", {}).get("beaconing", []):
        if b.get("community_id"):
            cids.append(b["community_id"])
    for cid in cids:
        if cid in seen or len(flows) >= caps["flows"]:
            continue
        seen.add(cid)
        r = run("get_flow_detail", drill.get_flow_detail, community_id=cid)
        if r is not None:
            flows.append(_sum_flow(r))
    out["flows"] = flows or {"checked": 0, "note": "위협/비콘 flow 없음"}

    # 3) victim 신원 + 내부 이동 검증 (측면이동 오탐/누락을 직접 막는 핵심)
    victims, _ = _derive_iocs(ev)
    dc_set = set(ev.get("conn", {}).get("ad_servers", []))  # →DC 인증은 정상 → 측면이동에서 제외
    vres = {}
    for ip in list(victims)[:caps["victims"]]:
        host = run("get_host_info", drill.get_host_info, ip=ip)
        # limit 크게 — 기본 20이면 DC 인증 flow가 먼저 차서 내부 측면이동 대상이 잘림
        conns = run("get_connections_by_ip", drill.get_connections_by_ip, ip=ip, limit=500)
        targets = set()
        if isinstance(conns, dict):
            for rec in conns.get("records", []):
                d, port = rec.get("id.resp_h"), rec.get("id.resp_p")
                if d and d != ip and d not in dc_set and _is_private(d) and port in LATERAL_PORTS:
                    targets.add(f"{d}:{port}")
        # evidence의 결정론적 lateral_movement(전체 로그 기반)도 합침 — 번들 잘림에 안전
        for lm in ev.get("conn", {}).get("lateral_movement", []):
            if lm.get("src") == ip and lm.get("dst"):
                targets.add(f"{lm['dst']}:{lm.get('dport')}")
        vres[ip] = {
            "host_info": {k: host.get(k) for k in ("hostname", "domain", "user", "mac", "role")}
                         if isinstance(host, dict) else host,
            "internal_admin_targets": sorted(targets) or "없음(내부 관리포트 연결 없음)",
        }
    out["victims"] = vres or {"checked": 0, "note": "위협 alert 기반 victim 없음"}

    # 4) 의심 도메인 확인
    dres = []
    for d in ev.get("enrichment", {}).get("dns", {}).get("suspicious", [])[:caps["dns"]]:
        if d.get("query"):
            r = run("search_dns", drill.search_dns, query_contains=d["query"])
            if r is not None:
                dres.append({"query": d["query"], "result": _sum_search(r, ("query", "answers"))})
    out["dns"] = dres or {"checked": 0, "note": "의심 도메인 없음"}

    # 5) 의심 HTTP 확인
    hres = []
    for h in ev.get("enrichment", {}).get("http", {}).get("suspicious", [])[:caps["http"]]:
        if h.get("host"):
            r = run("search_http", drill.search_http, host=h["host"])
            if r is not None:
                hres.append({"host": h["host"],
                             "result": _sum_search(r, ("host", "uri", "method", "resp_mime_types"))})
    out["http"] = hres or {"checked": 0, "note": "의심 HTTP 없음"}

    out["_calls"] = caps["total"] - budget[0]
    if budget[0] <= 0:
        out["_note"] = f"사전조사 예산 {caps['total']}회 소진 — 일부 신호 미조사(상한)"
    return out


def run_live(name, ev, base_url, api_key, model, max_rounds, temperature):
    drill = tools_mod.DrillDownTools(name)
    all_tools = tools_mod.TOOL_SCHEMAS + [SUBMIT_VERDICT_TOOL]
    trace = []   # tool 호출 기록 → verdict에 저장(사후 측정용)

    p(f"\n{'=' * 60}")
    p(f"  LLM 분석 시작: {name}")
    p(f"  model={model}  max_rounds={max_rounds}  tools={len(tools_mod.TOOL_SCHEMAS)}개")
    p(f"{'=' * 60}")

    # 강제 사전조사 — 모델이 추측하기 전에 코드가 필수 드릴다운을 먼저 돌려 근거를 깔아둔다
    p("\n  [사전조사] evidence 신호 기반 필수 드릴다운 강제 실행…")
    preinvest = essential_investigation(ev, drill, trace)
    _n = lambda v: len(v) if isinstance(v, list) else (len(v) if isinstance(v, dict) and "note" not in v else 0)
    p(f"  [사전조사] {preinvest.get('_calls', 0)}회 — malware {_n(preinvest['malware_files'])} / "
      f"flows {_n(preinvest['flows'])} / victims {_n(preinvest['victims'])} / "
      f"dns {_n(preinvest['dns'])} / http {_n(preinvest['http'])}")
    messages = build_messages(ev, preinvest)

    def finalize(args, r, note=None):
        v = enforce_review(dict(args), ev)
        v["tool_trace"] = trace
        v["rounds_used"] = r + 1
        if note:
            v.setdefault("rule_overrides", []).append(note)
        return v

    last_content = ""   # 마지막으로 본 본문 (막판 verdict 구제용)
    stalls = 0          # tool도 verdict도 못 뽑은 연속 라운드

    for r in range(max_rounds):
        p(f"\n── round {r} " + "─" * 40)
        resp = _chat(base_url, api_key, model, messages, all_tools, temperature)
        msg = resp["choices"][0]["message"]
        messages.append({k: v for k, v in msg.items() if v is not None})

        content = msg.get("content") or ""
        if content.strip():
            last_content = content
            p(f"  💭 {_preview(content, 400)}")

        tool_calls = msg.get("tool_calls") or []

        # (1) 정식 tool_call 경로 — 드릴다운 실행 / submit_verdict 제출
        if tool_calls:
            for tc in tool_calls:
                fn = tc["function"]["name"]
                try:
                    args = json.loads(tc["function"].get("arguments") or "{}")
                except json.JSONDecodeError:
                    args = {}
                if fn == "submit_verdict":
                    p("  ✅ submit_verdict 호출 — 최종 판정 제출")
                    return finalize(args, r)
                result = tools_mod.dispatch(drill, fn, args)
                size = len(json.dumps(result, ensure_ascii=False))
                trace.append({"round": r, "tool": fn, "args": args, "result_size": size})
                p(f"  🔧 {fn}({_preview(args, 120)})")
                p(f"      → ({size}자) {_preview(result, 220)}")
                messages.append({"role": "tool", "tool_call_id": tc["id"],
                                 "content": json.dumps(result, ensure_ascii=False)})
            stalls = 0
            continue

        # (2) tool_call 없음 → 본문에서 verdict 파싱. 나왔으면 '바로 채택하고 종료'
        #     (도구 안 쓰고 텍스트로 완결한 판정 = 더 돌려도 같은 답. round 0 결과를 버리지 않음)
        parsed = _extract_verdict(content)
        if parsed is not None:
            p("  ✅ content에서 verdict 파싱 — 채택하고 종료 (tool_call 미사용)")
            return finalize(parsed, r, "verdict를 tool_call이 아닌 content 텍스트에서 파싱(폴백)")

        # (3) tool도 verdict도 없음 → 한 번 유도, 반복되면 조기 종료(8라운드 낭비 방지)
        stalls += 1
        p(f"  ⚠️  tool 호출도 verdict도 없음 (stall {stalls})")
        if stalls >= 2:
            p("  ⏹  변화 없음 — 조기 종료")
            break
        messages.append({"role": "user",
                         "content": "Output ONLY the final verdict as a single JSON object "
                                    "(the submit_verdict arguments), or call a drill-down tool "
                                    "if you still need evidence."})

    # 루프 종료: 마지막 본문에서라도 verdict를 구제 (결과를 통째로 버리지 않는다)
    salvaged = _extract_verdict(last_content)
    if salvaged is not None:
        p("\n  ♻️  루프 종료 — 마지막 본문에서 verdict 구제")
        return finalize(salvaged, max_rounds - 1, "루프 종료 후 마지막 content에서 verdict 구제")
    p("\n  ❌ verdict를 한 번도 확보 못 함 — 판정 미제출")
    return {"error": "판정 미제출 (verdict 확보 실패)", "needs_review": True,
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
