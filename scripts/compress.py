#!/usr/bin/env python3
"""
compress.py — Zeek/Suricata 로그를 LLM 입력용 'evidence package'로 압축.

설계:
  1층(백본, 프로토콜 무관) : Suricata alert dedup + conn.log 통계 + 탐지기(비콘/스캔/측면이동)
  2층(enrichment, 있으면)  : http/dns/files/ssl 전용 압축기
  폴백                     : 등록 안 된 로그는 generic()이 "줄 수 + top값"으로 처리

원칙:
  - 결정론적 : 같은 입력 -> 같은 출력 (랜덤/LLM 없음)
  - 근거 보존 : 플래그마다 왜(숫자)를 같이 담음

사용법:
  python3 compress.py <pcap이름> [--out 경로] [--top N] [--md]
  예) python3 compress.py 2021-06-16-ISC-forensic-contest
경로 규칙:
  입력 <- output/zeek/<이름>/*.log , output/suricata/<이름>/eve.json
  출력 -> report/<이름>.evidence.json
"""
import argparse
import ipaddress
import json
import math
import os
import re
import statistics
from collections import Counter, defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ── 탐지 임계값 (한 곳에서 관리, 발표 때 근거로 제시) ──────────────
BEACON_MIN_CONNS = 5      # 비콘 판정 최소 연결 수
BEACON_CV_MAX    = 0.10   # 간격 변동계수(CV) 이하면 '규칙적' = 비콘
SCAN_MIN_PORTS   = 15     # 한 src가 한 dst에서 이만큼 포트 두드리면 스캔
LATERAL_PORTS    = {445: "SMB", 88: "Kerberos", 389: "LDAP", 135: "RPC", 3389: "RDP", 5985: "WinRM"}
DC_BASELINE_PORTS = {88, 389, 135, 445}  # 클라이언트→DC 정상 인증/도메인 포트 (측면이동 아님)
DC_FANIN_MIN      = 3                     # 내부 N+ 호스트가 Kerberos/LDAP 거는 내부IP = DC로 판정

# alert 분류 — 시그니처 접두사 기반. 위→아래 순서로 첫 매칭 적용.
# (버킷 순위가 낮을수록 위협. 발표 때 '왜 이 alert가 위/아래냐'의 근거)
ALERT_CLASS_RULES = [
    ("threat",     ["ET MALWARE", "ETPRO MALWARE", "ET TROJAN", "ET CNC", "ET EXPLOIT",
                    "ET ATTACK_RESPONSE", "ET WORM", "ET PHISHING", "ET DOS", "ET SHELLCODE",
                    "ET CURRENT_EVENTS", "ET WEB_SERVER", "ET ACTIVEX"]),
    ("suspicious", ["ET HUNTING", "ET SCAN", "ET POLICY", "ET JA3", "ET TLS", "ET DNS"]),
    ("info",       ["ET INFO", "ET P2P", "ET GAMES", "GPL "]),
    ("engine",     ["SURICATA ", "STREAM ", "DECODE ", "APPLAYER "]),
]
BUCKET_RANK = {"threat": 0, "suspicious": 1, "info": 2, "engine": 3, "other": 2}
# threat/suspicious는 절대 안 자름. info/engine만 이 한도로 truncate.
NOISE_BUCKET_LIMIT = 15


# ── 공통 유틸 ──────────────────────────────────────────────────
def read_zeek_log(path):
    """Zeek JSON 로그(.log) 한 파일 -> dict 리스트. 없으면 []."""
    if not os.path.exists(path):
        return []
    rows = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def read_eve(path):
    """Suricata eve.json -> event_type별로 분류한 dict."""
    out = defaultdict(list)
    if not os.path.exists(path):
        return out
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            out[e.get("event_type", "?")].append(e)
    return out


def is_private(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def is_real_host(ip):
    """프로파일 대상이 되는 '진짜 내부 호스트'인지 — broadcast/unspecified/multicast/reserved 제외.
       (0.0.0.0, 255.255.255.255 같은 가짜가 host_profiles에 끼는 것 방지.)"""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_private and not (a.is_multicast or a.is_unspecified
                                 or a.is_reserved or a.is_loopback)


def shannon_entropy(s):
    """문자열 엔트로피 — DGA(랜덤 도메인) 탐지용."""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# ── 1층: 백본 ─────────────────────────────────────────────────
def classify_alert(signature, severity=None):
    """버킷 분류. 접두사 매칭 우선, 미매칭 시 Suricata severity를 backstop으로 사용.

       접두사 목록은 손으로 관리라 항상 누락이 생긴다(예: ET RPC, ET DYN_DNS).
       그래서 매칭 실패해도 severity(룰에 박힌 ground truth: 1=위협/2=의심/3=정보)로
       분류해서 '위협이 other 버킷에 숨는' 사각지대를 없앤다."""
    sig = signature or ""
    for bucket, prefixes in ALERT_CLASS_RULES:
        if any(sig.startswith(p) for p in prefixes):
            return bucket
    # 접두사 미매칭 → severity로 backstop (모르면 일단 의심으로, 숨기지 않음)
    return {1: "threat", 2: "suspicious", 3: "info"}.get(severity, "suspicious")


def compress_alerts(alerts, top):
    """alert를 2단으로 압축 + 등급 분류 + 차등 truncation.

       반환:
         by_signature : 시그니처별 총합(헤드라인). threat/suspicious는 전부 포함,
                        info/engine만 NOISE_BUCKET_LIMIT로 자름.
         by_flow      : (시그니처,community_id)별 상세 — threat/suspicious만 (조인/드릴다운용).
         bucket_counts: 버킷별 alert 총량 (요약).
    """
    sig = defaultdict(lambda: {"count": 0, "flows": set(), "srcs": set(),
                               "dsts": set(), "dports": set()})
    flow = defaultdict(lambda: {"count": 0})
    bucket_counts = Counter()

    for a in alerts:
        al = a.get("alert", {})
        name = al.get("signature")
        cid = a.get("community_id")
        bucket = classify_alert(name, al.get("severity"))
        bucket_counts[bucket] += 1

        s = sig[name]
        s["count"] += 1
        s["signature"] = name
        s["category"] = al.get("category")
        s["severity"] = al.get("severity")
        s["bucket"] = bucket
        if cid:
            s["flows"].add(cid)
        if a.get("src_ip"):
            s["srcs"].add(a["src_ip"])
        if a.get("dest_ip"):
            s["dsts"].add(a["dest_ip"])
        if a.get("dest_port"):
            s["dports"].add(a["dest_port"])

        # flow 상세는 위협/의심만 (노이즈는 flow 단위로 안 남김)
        if bucket in ("threat", "suspicious"):
            g = flow[(name, cid)]
            g["count"] += 1
            g["signature"] = name
            g["bucket"] = bucket
            g["severity"] = al.get("severity")
            g["community_id"] = cid
            g["src"] = a.get("src_ip")
            g["dst"] = a.get("dest_ip")
            g["dport"] = a.get("dest_port")

    # by_signature 조립
    sig_rows = []
    for s in sig.values():
        sig_rows.append({
            "signature": s["signature"], "bucket": s["bucket"],
            "severity": s["severity"], "category": s["category"],
            "count": s["count"], "distinct_flows": len(s["flows"]),
            "src_ips": sorted(s["srcs"])[:5], "dst_ips": sorted(s["dsts"])[:5],
            "dports": sorted(p for p in s["dports"] if p)[:8],
        })

    # 차등 truncation: 위협/의심은 전부, 노이즈는 한도까지
    def sort_key(r):
        return (BUCKET_RANK.get(r["bucket"], 2), r["severity"] or 9, -r["count"])

    keep = [r for r in sig_rows if r["bucket"] in ("threat", "suspicious")]
    noise = [r for r in sig_rows if r["bucket"] not in ("threat", "suspicious")]
    keep.sort(key=sort_key)
    noise.sort(key=sort_key)
    by_signature = keep + noise[:NOISE_BUCKET_LIMIT]

    by_flow = sorted(flow.values(), key=lambda x: (BUCKET_RANK.get(x["bucket"], 2), -x["count"]))
    return {
        "by_signature": by_signature,
        "by_flow": by_flow[:top],
        "bucket_counts": dict(bucket_counts),
        "noise_truncated": max(0, len(noise) - NOISE_BUCKET_LIMIT),
    }


def detect_ad_servers(conn):
    """DC/AD 인프라를 행위로 식별 (결정론적).
       DC는 '여러 내부 호스트한테서 Kerberos(88)/LDAP(389)를 받는 내부 IP'다.
       이걸 알아야 클라이언트→DC 정상 인증을 측면이동 오탐에서 분리할 수 있다.
       (hostname 기반 판정은 build_host_profiles가 별도로 하며, 둘은 상호 보완)."""
    fanin = defaultdict(lambda: defaultdict(set))  # dst -> port -> {src}
    for c in conn:
        s, d, p = c.get("id.orig_h"), c.get("id.resp_h"), c.get("id.resp_p")
        if s and d and is_private(s) and is_private(d) and p in (88, 389):
            fanin[d][p].add(s)
    return {d for d, ports in fanin.items()
            if any(len(srcs) >= DC_FANIN_MIN for srcs in ports.values())}


def compress_conn(conn, top, dc_ips=None):
    """conn.log -> (src,dst,dport) 묶기 + 비콘/top-talker/스캔/측면이동 탐지.
       전부 프로토콜 무관 (conn.log엔 모든 flow가 들어옴).
       dc_ips: DC 집합. 내부→DC 정상 인증은 lateral이 아니라 ad_baseline으로 분리."""
    if dc_ips is None:
        dc_ips = detect_ad_servers(conn)
    groups = defaultdict(list)
    for r in conn:
        key = (r.get("id.orig_h"), r.get("id.resp_h"), r.get("id.resp_p"))
        groups[key].append(r)

    beacons, talkers, lateral, ad_baseline = [], [], [], []
    scan_tracker = defaultdict(set)  # src -> {(dst,port)} 로 스캔 추적

    for (src, dst, dport), conns in groups.items():
        ts = sorted(c["ts"] for c in conns if "ts" in c)
        total_bytes = sum((c.get("orig_bytes") or 0) + (c.get("resp_bytes") or 0) for c in conns)
        n = len(conns)
        service = conns[0].get("service") or conns[0].get("proto")
        cid = next((c.get("community_id") for c in conns if c.get("community_id")), None)

        # 비콘: 간격의 변동계수(CV)
        cv = None
        if len(ts) >= BEACON_MIN_CONNS:
            gaps = [ts[i + 1] - ts[i] for i in range(len(ts) - 1)]
            m = statistics.mean(gaps)
            if m > 0:
                cv = statistics.pstdev(gaps) / m
        rec = {"src": src, "dst": dst, "dport": dport, "service": service,
               "conns": n, "bytes": total_bytes, "community_id": cid}
        if cv is not None and cv <= BEACON_CV_MAX:
            beacons.append({**rec, "interval_cv": round(cv, 4),
                            "avg_interval_s": round(statistics.mean(gaps), 2),
                            "flag": "beacon", "why": f"간격 CV={cv:.4f} (규칙적)"})

        # top-talker: 외부로 나가는 대용량
        if not is_private(dst):
            talkers.append({**rec, "external": True})

        # 측면이동 vs 정상 AD 인증 분리:
        #   내부→DC 의 Kerberos/LDAP/RPC/SMB = 정상 도메인 인증 → ad_baseline (오탐 방지)
        #   내부→비DC 관리포트, 또는 DC라도 RDP/WinRM = 진짜 측면이동 후보
        if is_private(src) and is_private(dst) and dport in LATERAL_PORTS:
            if dst in dc_ips and dport in DC_BASELINE_PORTS:
                ad_baseline.append({**rec, "tech": LATERAL_PORTS[dport],
                                    "why": f"내부->DC {LATERAL_PORTS[dport]}({dport}) 정상 인증"})
            else:
                tgt = "DC" if dst in dc_ips else "내부호스트"
                lateral.append({**rec, "tech": LATERAL_PORTS[dport],
                                "why": f"내부->{tgt} {LATERAL_PORTS[dport]}({dport})"})

        # 스캔 추적
        scan_tracker[src].add((dst, dport))

    # 포트스캔: 한 src가 같은 dst에 많은 포트
    scans = []
    per_dst = defaultdict(lambda: defaultdict(set))
    for src, pairs in scan_tracker.items():
        for dst, port in pairs:
            per_dst[src][dst].add(port)
    for src, dsts in per_dst.items():
        for dst, ports in dsts.items():
            if len(ports) >= SCAN_MIN_PORTS:
                scans.append({"src": src, "dst": dst, "ports_touched": len(ports),
                              "flag": "port_scan", "why": f"{len(ports)}개 포트 접근"})

    talkers.sort(key=lambda x: -x["bytes"])
    beacons.sort(key=lambda x: -x["conns"])
    return {
        "flow_groups": len(groups),
        "ad_servers": sorted(dc_ips),
        "beaconing": beacons[:top],
        "top_talkers_external": talkers[:top],
        "lateral_movement": lateral[:top],
        "ad_baseline": ad_baseline[:top],
        "ad_baseline_count": len(ad_baseline),
        "port_scans": scans[:top],
    }


def join_alert_to_flow(alert_rows, conn):
    """community_id로 alert <-> flow 정보 보강 (조인 결과를 alert에 부착)."""
    flow_by_cid = {}
    for r in conn:
        cid = r.get("community_id")
        if cid and cid not in flow_by_cid:
            flow_by_cid[cid] = r
    for a in alert_rows:
        f = flow_by_cid.get(a.get("community_id"))
        if f:
            a["flow"] = {
                "service": f.get("service") or f.get("proto"),
                "duration_s": round(f.get("duration") or 0, 2),
                "bytes": (f.get("orig_bytes") or 0) + (f.get("resp_bytes") or 0),
                "conn_state": f.get("conn_state"),
            }
    return alert_rows


def _fmt_clock(ts):
    """epoch -> HH:MM:SS (UTC). 타임라인 표기용."""
    import time
    return time.strftime("%H:%M:%S", time.gmtime(ts))


def build_host_profiles(conn, ntlm, kerberos, top):
    """IP별 신원 통합 (가볍게, 내부 호스트만).
       conn에서 MAC/연결수, ntlm/kerberos에서 호스트명·도메인·유저를 모은다."""
    prof = {}

    def get(ip):
        return prof.setdefault(ip, {"conns": 0, "mac": None, "scope": "internal"})

    for c in conn:
        for ip, mac in ((c.get("id.orig_h"), c.get("orig_l2_addr")),
                        (c.get("id.resp_h"), c.get("resp_l2_addr"))):
            if not is_real_host(ip):   # 내부 '진짜' 호스트만 (broadcast/0.0.0.0 등 제외)
                continue
            p = get(ip)
            p["conns"] += 1
            if mac and not p["mac"]:
                p["mac"] = mac

    # NTLM에서 호스트명/도메인/유저 (클라이언트 IP 기준)
    for n in ntlm:
        ip = n.get("id.orig_h")
        if ip in prof:
            for src, dst in (("hostname", "hostname"), ("domainname", "domain"),
                             ("username", "user")):
                if n.get(src):
                    prof[ip].setdefault(dst, n[src])

    # Kerberos에서 유저 (호스트명 못 구한 경우 보조)
    for k in kerberos:
        ip = k.get("id.orig_h")
        if ip in prof and k.get("client") and "user" not in prof[ip]:
            prof[ip]["user"] = k["client"]

    # Kerberos service(SPN)에서 서버(주로 DC) 호스트명 — resp_h(서버) 기준.
    #   예: "ldap/enemywatch-dc.enemywatch.net" → 10.10.22.22 = ENEMYWATCH-DC
    #   (DC는 클라이언트가 아니라 서버라 client/NTLM엔 자기 이름이 안 떠서 SPN에서 보강)
    for k in kerberos:
        ip = k.get("id.resp_h")
        m = re.match(r"(?:ldap|cifs|host|http|gc|dns)/([^/\s@]+)", k.get("service") or "", re.I)
        if ip in prof and m and not prof[ip].get("hostname"):
            prof[ip]["hostname"] = m.group(1).split(".")[0].upper()

    # 역할 추정 (아주 단순): 호스트명에 DC 들어가면 도메인컨트롤러
    for ip, p in prof.items():
        host = (p.get("hostname") or "").upper()
        p["role"] = "domain_controller" if "DC" in host else "host"

    # 연결 많은 순으로 상한
    return dict(sorted(prof.items(), key=lambda kv: -kv[1]["conns"])[:top])


def build_timeline(conn, alerts, files, top, conn_summary=None):
    """실제 ts로 공격 흐름 뼈대를 구성 (결정론적).
       LLM은 이 뼈대를 '해석'만 한다 — 시간을 지어내지 않는다.
       이벤트 출처: 세션범위 / 멀웨어 다운로드 / 위협시그니처 첫발생 / 비콘 / 측면이동.
       alert·비콘·측면이동은 community_id로 conn의 실제 ts에 앵커링(시간 일관성 유지)."""
    conn_ts = [c["ts"] for c in conn if "ts" in c]
    if not conn_ts:
        return []
    start = min(conn_ts)
    # community_id -> 그 flow의 최초 ts
    ts_by_cid = {}
    for c in conn:
        cid, t = c.get("community_id"), c.get("ts")
        if cid and t is not None and (cid not in ts_by_cid or t < ts_by_cid[cid]):
            ts_by_cid[cid] = t

    events = []

    def add(ts, event, evidence=None):
        if ts is None:
            return
        events.append({"ts": round(ts, 3), "clock": _fmt_clock(ts),
                       "offset": f"+{ts - start:.0f}s", "event": event,
                       **({"evidence": evidence} if evidence else {})})

    # 세션 범위
    add(start, "캡처 세션 시작")
    add(max(conn_ts), "캡처 세션 종료")

    # 멀웨어 EXE 다운로드 (sha256별 최초)
    seen_sha = {}
    for f in files:
        mime = f.get("mime_type", "")
        if ("dosexec" in mime or "executable" in mime) and f.get("sha256"):
            sha, t = f["sha256"], f.get("ts")
            if t is not None and (sha not in seen_sha or t < seen_sha[sha]):
                seen_sha[sha] = t
    for sha, t in seen_sha.items():
        add(t, f"실행파일 다운로드 ({sha[:12]}…)", f"sha256:{sha}")

    # 위협/의심 시그니처 첫 발생 (community_id로 실제 flow ts에 앵커링)
    sig_first = {}
    for a in alerts:
        al = a.get("alert", {})
        bucket = classify_alert(al.get("signature"), al.get("severity"))
        if bucket not in ("threat", "suspicious"):
            continue
        t = ts_by_cid.get(a.get("community_id"))
        name = al.get("signature")
        if t is not None and (name not in sig_first or t < sig_first[name][0]):
            sig_first[name] = (t, a.get("community_id"))
    for name, (t, cid) in sig_first.items():
        add(t, f"IDS 첫 탐지: {name}", f"community_id:{cid}")

    # 비콘 시작 시각 / 측면이동 — community_id로 conn 실제 ts에 앵커링 (docstring·프롬프트 약속 이행)
    cs = conn_summary or {}
    for b in cs.get("beaconing", []):
        add(ts_by_cid.get(b.get("community_id")),
            f"비콘 패턴: {b.get('src')} → {b.get('dst')}:{b.get('dport')} "
            f"({b.get('conns')}회, CV={b.get('interval_cv')})",
            f"community_id:{b.get('community_id')}")
    for lm in cs.get("lateral_movement", []):
        add(ts_by_cid.get(lm.get("community_id")),
            f"측면이동 의심: {lm.get('src')} → {lm.get('dst')}:{lm.get('dport')} {lm.get('tech')}",
            f"community_id:{lm.get('community_id')}")

    # 정렬 + 중복 정리 + 상한
    events.sort(key=lambda e: e["ts"])
    return events[: max(top, 30)]


# ── 2층: enrichment (있으면 동작) ──────────────────────────────
def compress_http(http, top):
    susp = []
    host_ua = Counter()
    for r in http:
        host = r.get("host", "")
        ua = r.get("user_agent", "")
        host_ua[(host, ua)] += 1
        mimes = " ".join(r.get("resp_mime_types") or [])
        reasons = []
        if "dosexec" in mimes or "executable" in mimes:
            reasons.append("실행파일 다운로드")
        if r.get("method") == "POST" and host and host.replace(".", "").isdigit():
            reasons.append("dotted-quad(IP)로 POST")
        if reasons:
            susp.append({"host": host, "uri": (r.get("uri") or "")[:80],
                         "method": r.get("method"), "mime": mimes,
                         "src": r.get("id.orig_h"), "dst": r.get("id.resp_h"),
                         "why": ", ".join(reasons)})
    return {"records": len(http),
            "suspicious": susp[:top],
            "top_host_ua": [{"host": h, "ua": u[:60], "count": c}
                            for (h, u), c in host_ua.most_common(top)]}


def compress_dns(dns, top):
    susp, q = [], Counter()
    for r in dns:
        query = r.get("query", "")
        if not query:
            continue
        q[query] += 1
        labels = query.split(".")
        longest = max(labels, key=len) if labels else ""
        ent = shannon_entropy(longest)
        reasons = []
        if ent >= 3.5 and len(longest) >= 12:
            reasons.append(f"고엔트로피({ent:.1f}) DGA 의심")
        for ans in (r.get("answers") or []):
            if isinstance(ans, str) and "ipify" in query.lower():
                reasons.append("외부IP조회 서비스")
        if reasons:
            susp.append({"query": query[:80], "entropy": round(ent, 2),
                         "src": r.get("id.orig_h"), "why": ", ".join(reasons)})
    return {"records": len(dns), "unique_queries": len(q),
            "suspicious": susp[:top]}


def compress_files(files, top):
    """실행파일만 추려 SHA256 (멀웨어 신원조회 입력). 해시로 dedup."""
    by_hash = defaultdict(lambda: {"count": 0})
    incomplete = 0
    for f in files:
        mime = f.get("mime_type", "")
        if "dosexec" not in mime and "executable" not in mime:
            continue
        h = f.get("sha256")
        if not h:
            incomplete += 1
            continue
        g = by_hash[h]
        g["count"] += 1
        g["sha256"] = h
        g["md5"] = f.get("md5")
        g["size"] = f.get("seen_bytes")
        g["mime"] = mime
    return {"records": len(files),
            "malware_candidates": sorted(by_hash.values(), key=lambda x: -x["count"])[:top],
            "incomplete_executables": incomplete}


def compress_ssl(ssl, top):
    susp, ja3 = [], Counter()
    for r in ssl:
        if r.get("ja3"):
            ja3[r["ja3"]] += 1
        if r.get("validation_status") and r["validation_status"] != "ok":
            susp.append({"server_name": r.get("server_name"),
                         "validation": r.get("validation_status"),
                         "dst": r.get("id.resp_h")})
    return {"records": len(ssl),
            "top_ja3": [{"ja3": k, "count": v} for k, v in ja3.most_common(top)],
            "bad_validation": susp[:top]}


# ── 폴백: 등록 안 된 로그 전부 ──────────────────────────────────
def generic(rows, top):
    """줄 수 + 주요 컬럼 top값. 어떤 로그가 와도 안 깨짐."""
    if not rows:
        return {"records": 0}
    # id/uid/ts 같은 식별자 제외하고, 값 다양성 낮은 컬럼만 요약
    keys = [k for k in rows[0].keys()
            if not k.startswith("id.") and k not in ("ts", "uid", "fuid")]
    summary = {}
    for k in keys:
        vals = Counter(str(r.get(k)) for r in rows if r.get(k) is not None)
        if 0 < len(vals) <= 50:  # 카디널리티 낮은 것만 (의미있는 범주형)
            summary[k] = dict(vals.most_common(min(top, 10)))
    return {"records": len(rows), "top_values": summary}


# 전용 압축기 등록부 — 없으면 generic으로 빠짐
REGISTRY = {
    "http": compress_http,
    "dns": compress_dns,
    "files": compress_files,
    "ssl": compress_ssl,
}


def assess_status(pkts, flows, alert_events, zeek_log_count):
    """파이프라인 건강 상태 판정 — '실패가 정상으로 위장'하는 것 방지.
       pkts: 입력 패킷 수(None이면 모름). 핵심 규칙: 신호 0인데 '정상'이라 하지 않는다."""
    warnings = []
    # 입력 자체를 못 읽음 (지원 안 하는 포맷 등)
    if pkts == 0:
        warnings.append("입력 패킷 0개 — 지원 안 하는 캡처 포맷이거나 손상 (libpcap이 못 읽음)")
        return "FAILED_TO_PARSE", warnings
    if zeek_log_count == 0 and alert_events == 0:
        warnings.append("Zeek 로그 0 + Suricata 이벤트 0 — 파싱 실패 가능성 높음")
        return "FAILED_TO_PARSE", warnings
    # 읽긴 했으나 IP flow가 없음 (비IP 트래픽 등)
    if flows == 0:
        warnings.append("IP flow 0개 — 비IP 트래픽이거나 부분 파싱 (conn.log 없음)")
        return "NO_IP_FLOWS", warnings
    # 정상 파싱. 위협 유무는 분석 결과지 상태가 아님
    return "OK", warnings


# ── 메인 조립 ─────────────────────────────────────────────────
def build_evidence(name, zeek_dir, eve_path, top, pkts=None):
    conn = read_zeek_log(os.path.join(zeek_dir, "conn.log"))
    eve = read_eve(eve_path)
    alerts = eve.get("alert", [])

    # 호스트 신원 프로파일 먼저 — DC를 '행위(Kerberos/LDAP fan-in)'와 'hostname' 둘 다로 식별해
    # 작은 캡처(fan-in 부족)에서도 DC를 놓치지 않게 한다. (AD 정상 인증 오탐 방지의 핵심)
    host_profiles = build_host_profiles(
        conn, read_zeek_log(os.path.join(zeek_dir, "ntlm.log")),
        read_zeek_log(os.path.join(zeek_dir, "kerberos.log")), top)
    dc_ips = detect_ad_servers(conn) | {ip for ip, p in host_profiles.items()
                                        if p.get("role") == "domain_controller"}

    # 1층 백본
    alerts_pkg = compress_alerts(alerts, top)
    alerts_pkg["by_flow"] = join_alert_to_flow(alerts_pkg["by_flow"], conn)
    conn_summary = compress_conn(conn, top, dc_ips=dc_ips)

    # 타임라인 뼈대 (실제 ts 기반 — LLM은 해석만)
    files_raw = read_zeek_log(os.path.join(zeek_dir, "files.log"))
    timeline = build_timeline(conn, alerts, files_raw, top, conn_summary)

    zeek_log_count = len([f for f in os.listdir(zeek_dir)
                          if f.endswith(".log") and f[:-4] not in
                          ("packet_filter", "loaded_scripts", "reporter")]) if os.path.isdir(zeek_dir) else 0

    pkg = {
        "meta": {
            "pcap": name,
            "input_packets": pkts,
            "flows": len(conn),
            "alert_events": len(alerts),
            "alert_buckets": alerts_pkg["bucket_counts"],
            "alert_signatures": len(alerts_pkg["by_signature"]),
        },
        "ids_alerts": alerts_pkg,
        "conn": conn_summary,
        "host_profiles": host_profiles,
        "timeline": timeline,
        "enrichment": {},
        "other_protocols": {},
    }

    # 2층 + 폴백: 존재하는 모든 zeek 로그 순회 (디렉토리 없거나 비어도 안전)
    for fn in sorted(os.listdir(zeek_dir)) if os.path.isdir(zeek_dir) else []:
        if not fn.endswith(".log"):
            continue
        logname = fn[:-4]
        if logname in ("conn", "packet_filter", "loaded_scripts", "reporter"):
            continue  # conn은 위에서 처리, 운영 로그는 스킵
        rows = read_zeek_log(os.path.join(zeek_dir, fn))
        if not rows:
            continue
        if logname in REGISTRY:
            pkg["enrichment"][logname] = REGISTRY[logname](rows, top)
        else:
            pkg["other_protocols"][logname] = generic(rows, top)

    # 상태 판정 — 실패/비IP를 '정상'과 명확히 구분해서 meta에 스탬프
    status, warnings = assess_status(pkts, len(conn), len(alerts), zeek_log_count)
    pkg["meta"]["status"] = status
    pkg["meta"]["warnings"] = warnings
    return pkg


# ── 드릴다운 번들: tool이 Colab에서도 동작하도록 evidence와 함께 동봉 ──
# output/ 전체(수십 MB)는 .gitignore라 Colab clone에 안 따라간다. 그러면 tools.py가
# 읽을 원본이 없어 모든 드릴다운이 "없음"으로 실패한다(실측 확인). 그래서 '외부통신 +
# 위협 관련 + 신원' 레코드만 추려 report/<name>.drilldown.json으로 같이 커밋한다.
DRILL_CAPS = {"conn": 1000, "http": 600, "dns": 1500, "ssl": 500, "files": 300, "alerts": 800}


def _external_flow(c):
    o, r = c.get("id.orig_h"), c.get("id.resp_h")
    return bool((o and not is_private(o)) or (r and not is_private(r)))


def build_drilldown(zeek_dir, eve_path):
    """tool 드릴다운용 원본 레코드 부분집합 (결정론적, 상한 적용)."""
    conn = read_zeek_log(os.path.join(zeek_dir, "conn.log"))
    alerts = read_eve(eve_path).get("alert", [])

    def is_sig_relevant(a):
        al = a.get("alert", {})
        return classify_alert(al.get("signature"), al.get("severity")) in ("threat", "suspicious")

    # 위협/의심 alert가 가리키는 flow는 반드시 포함
    ref_cids = {a.get("community_id") for a in alerts if is_sig_relevant(a) and a.get("community_id")}

    # conn: 외부통신 / 위협 flow / 내부 측면이동(관리포트) 만 추림 (내부 AD 잡음 제거).
    # 잘림 우선순위 중요: 위협참조·측면이동은 rare·high-value라 무조건 보존하고,
    # 대량 외부통신만 남는 예산으로 자른다(원본 순서대로 자르면 측면이동이 외부통신에 밀려 사라짐).
    ref_conn, lat_conn, ext_conn = [], [], []
    for c in conn:
        o, r, dp = c.get("id.orig_h"), c.get("id.resp_h"), c.get("id.resp_p")
        if c.get("community_id") in ref_cids:
            ref_conn.append(c)
        elif o and r and is_private(o) and is_private(r) and dp in LATERAL_PORTS:
            lat_conn.append(c)
        elif _external_flow(c):
            ext_conn.append(c)
    cap = DRILL_CAPS["conn"]
    priority = ref_conn + lat_conn
    kept_conn = priority[:cap] + ext_conn[:max(0, cap - len(priority))]
    kept_uids = {c.get("uid") for c in kept_conn}

    def link(logname, cap, extra=None):
        rows = read_zeek_log(os.path.join(zeek_dir, f"{logname}.log"))
        out = [r for r in rows if r.get("uid") in kept_uids or (extra and extra(r))]
        return out[:cap]

    ext_resp = lambda r: r.get("id.resp_h") and not is_private(r["id.resp_h"])

    # 위협/의심 alert를 (signature, community_id, src, dst)로 중복 제거
    seen, alert_rows = set(), []
    for a in alerts:
        if not is_sig_relevant(a):
            continue
        al = a.get("alert", {})
        k = (al.get("signature"), a.get("community_id"), a.get("src_ip"), a.get("dest_ip"))
        if k in seen:
            continue
        seen.add(k)
        alert_rows.append(a)

    return {
        "conn": kept_conn,
        "http": link("http", DRILL_CAPS["http"], ext_resp),
        # DNS는 내부 리졸버(내부→내부)로 가도 쿼리 내용이 중요 → uid 무관하게 전부 포함
        "dns": read_zeek_log(os.path.join(zeek_dir, "dns.log"))[:DRILL_CAPS["dns"]],
        "ssl": link("ssl", DRILL_CAPS["ssl"], ext_resp),
        "files": read_zeek_log(os.path.join(zeek_dir, "files.log"))[:DRILL_CAPS["files"]],
        "ntlm": read_zeek_log(os.path.join(zeek_dir, "ntlm.log")),       # 신원 (작음, 전부)
        "kerberos": read_zeek_log(os.path.join(zeek_dir, "kerberos.log")),
        "alerts": alert_rows[:DRILL_CAPS["alerts"]],
    }


def to_markdown(pkg):
    m = pkg["meta"]
    lines = [f"# Evidence: {m['pcap']}",
             f"- flows: {m['flows']} / alert: {m['alert_events']} "
             f"(buckets: {m['alert_buckets']})", ""]
    lines.append("## IDS Alerts — 시그니처별 (위협 우선, 위협/의심은 안 잘림)")
    for a in pkg["ids_alerts"]["by_signature"]:
        if a["bucket"] not in ("threat", "suspicious"):
            continue
        lines.append(f"- [{a['count']:>6}x / {a['distinct_flows']}flows] "
                     f"({a['bucket']}/sev{a['severity']}) {a['signature']}  "
                     f"{a['src_ips']}->{a['dst_ips']}")
    nt = pkg["ids_alerts"].get("noise_truncated", 0)
    lines.append(f"\n_(info/engine 노이즈 버킷은 생략, {nt}종 추가 잘림)_")
    lines.append("\n## Beaconing")
    for b in pkg["conn"]["beaconing"][:10]:
        lines.append(f"- {b['src']} -> {b['dst']}:{b['dport']}  "
                     f"{b['conns']}회 CV={b['interval_cv']}  ({b['why']})")
    lines.append("\n## Malware files (SHA256)")
    for f in pkg["enrichment"].get("files", {}).get("malware_candidates", [])[:10]:
        lines.append(f"- {f['sha256'][:16]}... {f['size']}B x{f['count']}")
    lines.append("\n## Timeline (실제 ts 기반)")
    for e in pkg.get("timeline", [])[:20]:
        lines.append(f"- {e['clock']} ({e['offset']}) {e['event']}")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("name", help="pcap 이름 (확장자 제외)")
    ap.add_argument("--out", default=None)
    ap.add_argument("--top", type=int, default=20)
    ap.add_argument("--md", action="store_true", help="사람용 markdown도 출력")
    ap.add_argument("--pkts", type=int, default=None,
                    help="입력 pcap 패킷 수 (상태 판정용. orchestrator가 전달)")
    args = ap.parse_args()

    zeek_dir = os.path.join(ROOT, "output", "zeek", args.name)
    eve_path = os.path.join(ROOT, "output", "suricata", args.name, "eve.json")
    # zeek_dir 없어도 죽지 않고 'FAILED' 패키지를 만든다 (실패도 결과로 남겨야 함)

    pkg = build_evidence(args.name, zeek_dir, eve_path, args.top, pkts=args.pkts)

    out = args.out or os.path.join(ROOT, "report", f"{args.name}.evidence.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(pkg, f, ensure_ascii=False, indent=2)

    # 드릴다운 번들 동봉 — tool이 Colab(원본 로그 없음)에서도 동작하도록. gzip으로 git 부담 최소화.
    if pkg["meta"]["status"] == "OK":
        import gzip
        drill = build_drilldown(zeek_dir, eve_path)
        # out이 .evidence.json로 안 끝나면 replace가 무동작 → gz가 evidence를 덮어쓰는 버그 방지
        if out.endswith(".evidence.json"):
            drill_out = out[:-len(".evidence.json")] + ".drilldown.json.gz"
        else:
            drill_out = out + ".drilldown.json.gz"
        with gzip.open(drill_out, "wt", encoding="utf-8") as f:
            json.dump(drill, f, ensure_ascii=False)
        kb = os.path.getsize(drill_out) // 1024
        print(f"[+] drilldown bundle -> {drill_out}  "
              f"({ {k: len(v) for k, v in drill.items()} }, {kb}KB gz)")

    st = pkg["meta"]["status"]
    icon = {"OK": "✅", "NO_IP_FLOWS": "⚠️", "FAILED_TO_PARSE": "❌"}.get(st, "?")
    print(f"[+] evidence package -> {out}")
    print(f"    {icon} status={st}  pkts={pkg['meta']['input_packets']} / "
          f"flows {pkg['meta']['flows']} / alert {pkg['meta']['alert_events']}")
    for w in pkg["meta"]["warnings"]:
        print(f"      ⚠️  {w}")
    if st == "OK":
        b = pkg["meta"]["alert_buckets"]
        print(f"    시그니처 {pkg['meta']['alert_signatures']}종 {b}  |  "
              f"비콘 {len(pkg['conn']['beaconing'])} / 측면이동 {len(pkg['conn']['lateral_movement'])} / "
              f"멀웨어파일 {len(pkg['enrichment'].get('files',{}).get('malware_candidates',[]))}")

    if args.md:
        md = out.replace(".json", ".md")
        with open(md, "w", encoding="utf-8") as f:
            f.write(to_markdown(pkg))
        print(f"[+] markdown -> {md}")


if __name__ == "__main__":
    main()
