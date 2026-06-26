#!/usr/bin/env python3
"""
tools.py — LLM function-calling용 드릴다운 도구 (티어③: 필요할 때만 원본 로그 조회).

LLM은 평소 evidence package(요약)만 본다. 더 깊이 봐야 할 때 아래 도구를 호출해
디스크의 Zeek/Suricata 원본 로그에서 해당 부분만 꺼내온다.

원칙:
  - 읽기 전용 (원본 로그 절대 수정 안 함)
  - 출력 제한(limit) — 대량 레코드가 context를 폭파시키지 않게 잘라서 반환
  - Zeek uid로 로그 간 상관 (community_id로 conn 찾고 → uid로 http/dns/ssl/files 연결)

단독 테스트:
  python3 tools.py <pcap이름>
"""
import json
import os

from compress import read_eve, read_zeek_log  # 로그 파서 재사용

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# LLM에 되돌려줄 때 토큰 절약을 위해 레코드에서 남길 필드만 추림
CONN_FIELDS = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
               "proto", "service", "duration", "orig_bytes", "resp_bytes",
               "conn_state", "history", "community_id"]
HTTP_FIELDS = ["ts", "uid", "id.orig_h", "id.resp_h", "method", "host", "uri",
               "user_agent", "status_code", "request_body_len",
               "response_body_len", "resp_mime_types"]
DNS_FIELDS = ["ts", "uid", "id.orig_h", "query", "qtype_name", "rcode_name", "answers"]
SSL_FIELDS = ["ts", "uid", "version", "cipher", "server_name", "ja3", "validation_status"]


def _pick(rec, fields):
    """레코드에서 지정 필드만 추출 (없는 건 생략)."""
    return {k: rec[k] for k in fields if k in rec}


class DrillDownTools:
    """한 pcap의 원본 로그에 대한 드릴다운 도구 모음. pcap당 1개 인스턴스."""

    def __init__(self, name, root=ROOT):
        self.name = name
        self.zeek_dir = os.path.join(root, "output", "zeek", name)
        self.eve_path = os.path.join(root, "output", "suricata", name, "eve.json")
        self.extract_dir = os.path.join(self.zeek_dir, "extract_files")
        self._cache = {}  # 로그를 한 번만 읽어 캐시

    def _log(self, logname):
        if logname not in self._cache:
            self._cache[logname] = read_zeek_log(os.path.join(self.zeek_dir, f"{logname}.log"))
        return self._cache[logname]

    def _alerts(self):
        if "_alerts" not in self._cache:
            self._cache["_alerts"] = read_eve(self.eve_path).get("alert", [])
        return self._cache["_alerts"]

    # ── 1. flow 상세 (community_id → 그 flow의 모든 프로토콜 레코드) ──
    def get_flow_detail(self, community_id, limit=20):
        """community_id로 conn 찾고, 그 uid로 http/dns/ssl/files까지 묶어 반환."""
        conns = [c for c in self._log("conn") if c.get("community_id") == community_id]
        if not conns:
            return {"error": f"community_id '{community_id}'에 해당하는 flow 없음"}
        uids = {c.get("uid") for c in conns}
        out = {
            "community_id": community_id,
            "conn": [_pick(c, CONN_FIELDS) for c in conns[:limit]],
            "http": [_pick(h, HTTP_FIELDS) for h in self._log("http") if h.get("uid") in uids][:limit],
            "dns": [_pick(d, DNS_FIELDS) for d in self._log("dns") if d.get("uid") in uids][:limit],
            "ssl": [_pick(s, SSL_FIELDS) for s in self._log("ssl") if s.get("uid") in uids][:limit],
            "files": [{"sha256": f.get("sha256"), "mime_type": f.get("mime_type"),
                       "seen_bytes": f.get("seen_bytes")}
                      for f in self._log("files") if f.get("uid") in uids][:limit],
        }
        return out

    # ── 2. HTTP 검색 ──
    def search_http(self, host=None, uri_contains=None, limit=20):
        """host 또는 uri 키워드로 HTTP 원본 레코드 검색."""
        res = []
        for h in self._log("http"):
            if host and host.lower() not in (h.get("host") or "").lower():
                continue
            if uri_contains and uri_contains.lower() not in (h.get("uri") or "").lower():
                continue
            res.append(_pick(h, HTTP_FIELDS))
        return {"matched": len(res), "records": res[:limit]}

    # ── 3. DNS 검색 ──
    def search_dns(self, query_contains=None, limit=20):
        """query 키워드로 DNS 원본 레코드 검색."""
        res = []
        for d in self._log("dns"):
            if query_contains and query_contains.lower() not in (d.get("query") or "").lower():
                continue
            res.append(_pick(d, DNS_FIELDS))
        return {"matched": len(res), "records": res[:limit]}

    # ── 4. Suricata alert 검색 (원문) ──
    def search_alerts(self, signature_contains=None, src=None, dst=None, limit=20):
        """시그니처 키워드 / 출발·도착 IP로 alert 원문 검색."""
        res = []
        for a in self._alerts():
            sig = a.get("alert", {}).get("signature", "")
            if signature_contains and signature_contains.lower() not in sig.lower():
                continue
            if src and a.get("src_ip") != src:
                continue
            if dst and a.get("dest_ip") != dst:
                continue
            res.append({"signature": sig, "severity": a["alert"].get("severity"),
                        "category": a["alert"].get("category"),
                        "src": a.get("src_ip"), "dst": a.get("dest_ip"),
                        "dport": a.get("dest_port"), "community_id": a.get("community_id")})
        return {"matched": len(res), "records": res[:limit]}

    # ── 5. IP 기준 통신 조회 ──
    def get_connections_by_ip(self, ip, limit=20):
        """특정 IP가 관여한 flow 전부 (출발이든 도착이든)."""
        res = [_pick(c, CONN_FIELDS) for c in self._log("conn")
               if c.get("id.orig_h") == ip or c.get("id.resp_h") == ip]
        return {"ip": ip, "matched": len(res), "records": res[:limit]}

    # ── 6. 멀웨어 파일 조회 (sha256 → 메타 + 추출경로) ──
    def get_malware_file(self, sha256, limit=20):
        """sha256으로 files.log 메타 + extract_files/의 추출 파일 경로 매칭."""
        recs = [f for f in self._log("files") if f.get("sha256") == sha256]
        if not recs:
            return {"error": f"sha256 '{sha256[:16]}...'에 해당하는 파일 없음"}
        fuids = {f.get("fuid") for f in recs}
        extracted = []
        if os.path.isdir(self.extract_dir):
            for fn in os.listdir(self.extract_dir):
                if any(fuid and fuid in fn for fuid in fuids):
                    extracted.append(os.path.join(self.extract_dir, fn))
        r = recs[0]
        return {"sha256": sha256, "md5": r.get("md5"), "mime_type": r.get("mime_type"),
                "seen_bytes": r.get("seen_bytes"), "download_count": len(recs),
                "extracted_paths": extracted[:limit]}

    # ── 7. 호스트 신원 (IP 또는 MAC → 호스트명/도메인/유저/MAC) ──
    def get_host_info(self, ip=None, mac=None):
        """IP나 MAC으로 호스트 신원 조회 (conn의 MAC + ntlm/kerberos의 호스트명·유저)."""
        info = {"ip": ip, "mac": mac, "scope": ("internal" if ip and self._is_private(ip) else "external")}
        # conn에서 MAC / 상대 IP 수집
        for c in self._log("conn"):
            if ip and c.get("id.orig_h") == ip and c.get("orig_l2_addr"):
                info["mac"] = c["orig_l2_addr"]
            if ip and c.get("id.resp_h") == ip and c.get("resp_l2_addr"):
                info["mac"] = c["resp_l2_addr"]
            if mac and c.get("orig_l2_addr") == mac:
                info["ip"] = c.get("id.orig_h")
        tgt = info.get("ip")
        for n in self._log("ntlm"):
            if n.get("id.orig_h") == tgt:
                for s, d in (("hostname", "hostname"), ("domainname", "domain"), ("username", "user")):
                    if n.get(s):
                        info.setdefault(d, n[s])
        for k in self._log("kerberos"):
            if k.get("id.orig_h") == tgt and k.get("client") and "user" not in info:
                info["user"] = k["client"]
        return info if (info.get("hostname") or info.get("user") or info.get("mac")) \
            else {**info, "note": "추가 신원정보 없음 (외부IP거나 인증트래픽 없음)"}

    @staticmethod
    def _is_private(ip):
        import ipaddress
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False


# ── OpenAI 호환 function-calling 스키마 (vLLM/Qwen이 이 형식 사용) ──
TOOL_SCHEMAS = [
    {"type": "function", "function": {
        "name": "get_flow_detail",
        "description": "community_id로 특정 flow의 conn/http/dns/ssl/files 원본 레코드를 모두 조회",
        "parameters": {"type": "object", "properties": {
            "community_id": {"type": "string", "description": "조회할 flow의 community_id"}},
            "required": ["community_id"]}}},
    {"type": "function", "function": {
        "name": "search_http",
        "description": "host 또는 URI 키워드로 HTTP 요청 원본 검색",
        "parameters": {"type": "object", "properties": {
            "host": {"type": "string"}, "uri_contains": {"type": "string"}}}}},
    {"type": "function", "function": {
        "name": "search_dns",
        "description": "도메인 질의 키워드로 DNS 원본 검색",
        "parameters": {"type": "object", "properties": {
            "query_contains": {"type": "string"}}}}},
    {"type": "function", "function": {
        "name": "search_alerts",
        "description": "시그니처 키워드 또는 출발/도착 IP로 Suricata alert 원문 검색",
        "parameters": {"type": "object", "properties": {
            "signature_contains": {"type": "string"}, "src": {"type": "string"},
            "dst": {"type": "string"}}}}},
    {"type": "function", "function": {
        "name": "get_connections_by_ip",
        "description": "특정 IP가 관여한 모든 flow 조회",
        "parameters": {"type": "object", "properties": {
            "ip": {"type": "string"}}, "required": ["ip"]}}},
    {"type": "function", "function": {
        "name": "get_malware_file",
        "description": "sha256으로 추출된 멀웨어 파일의 메타데이터와 디스크 경로 조회",
        "parameters": {"type": "object", "properties": {
            "sha256": {"type": "string"}}, "required": ["sha256"]}}},
    {"type": "function", "function": {
        "name": "get_host_info",
        "description": "IP 또는 MAC으로 호스트 신원(호스트명/도메인/유저/MAC) 조회",
        "parameters": {"type": "object", "properties": {
            "ip": {"type": "string"}, "mac": {"type": "string"}}}}},
]


def dispatch(tools, tool_name, arguments):
    """LLM이 호출한 도구를 실제 메서드로 라우팅. 결과 dict 반환."""
    fn = getattr(tools, tool_name, None)
    if fn is None or tool_name.startswith("_"):
        return {"error": f"알 수 없는 도구: {tool_name}"}
    try:
        return fn(**arguments)
    except TypeError as e:
        return {"error": f"인자 오류: {e}"}


# ── 단독 테스트 (LLM 없이 도구 동작 검증) ──
if __name__ == "__main__":
    import sys
    name = sys.argv[1] if len(sys.argv) > 1 else "2021-06-16-ISC-forensic-contest"
    t = DrillDownTools(name)

    # evidence.json에서 테스트용 community_id / sha256 자동 추출
    ev_path = os.path.join(ROOT, "report", f"{name}.evidence.json")
    cid = sha = None
    if os.path.exists(ev_path):
        ev = json.load(open(ev_path))
        beacons = ev["conn"]["beaconing"]
        if beacons:
            cid = beacons[0].get("community_id")
        mals = ev["enrichment"].get("files", {}).get("malware_candidates", [])
        if mals:
            sha = mals[0].get("sha256")

    print(f"=== tools.py 단독 테스트: {name} ===\n")
    if cid:
        print(f"[1] get_flow_detail({cid[:24]}...)")
        d = t.get_flow_detail(cid)
        print(f"    conn {len(d.get('conn', []))} / http {len(d.get('http', []))} / "
              f"dns {len(d.get('dns', []))} / ssl {len(d.get('ssl', []))} / files {len(d.get('files', []))}")
    print("\n[4] search_alerts(signature_contains='Cobalt')")
    print("   ", t.search_alerts(signature_contains="Cobalt")["matched"], "건 매칭")
    print("\n[3] search_dns(query_contains='.com') (상위 일부)")
    print("   ", t.search_dns(query_contains=".com")["matched"], "건 매칭")
    if sha:
        print(f"\n[6] get_malware_file({sha[:16]}...)")
        print("   ", json.dumps(t.get_malware_file(sha), ensure_ascii=False)[:200])
