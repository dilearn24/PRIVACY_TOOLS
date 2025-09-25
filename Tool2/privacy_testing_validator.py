"""
privacy_testing_validator.py
Outputs:
  out/privacy_test_results.json
  out/privacy_test_results.txt
  out/requests.log
"""

from __future__ import annotations
import argparse, json, os, re, sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import urllib.request, urllib.error, http.cookiejar

# ---------- Config / defaults ----------
SEVERITY_ORDER = {"info":0, "low":1, "medium":2, "high":3, "critical":4}
DEFAULT_ENDPOINTS = ["/", "/api", "/login", "/signup", "/profile", "/account", "/users", "/privacy"]
DEFAULT_FORM_PATHS = ["/signup", "/register", "/account", "/profile"]
DEFAULT_PRIVACY_CANDIDATES = ["/privacy", "/legal/privacy", "/settings"]
DEFAULT_TIMEOUT = 5
PRIVACY_HINTS = ("privacy policy", "data protection", "gdpr")

# ---------- Logging ----------
log_file = None
def log_init(outdir: Path):
    global log_file
    outdir.mkdir(parents=True, exist_ok=True)
    log_file = open(outdir / "requests.log", "w", encoding="utf-8")
    log("logging -> requests.log")

def log(msg: str):
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    line = f"[{ts}] {msg}"
    print(f"[validator] {line}", file=sys.stderr)
    if log_file:
        log_file.write(line + "\n"); log_file.flush()

# ---------- Small Response shim ----------
class Resp:
    def __init__(self, url: str, status: int, headers: Dict[str,str], body: str, cookies: List[str], history: List[str]):
        self.url = url
        self.status_code = status
        self.headers = headers
        self.text = body
        self.cookies = cookies        # names only
        self.history = history        # redirect chain (urls)

# ---------- HTTP (urllib) ----------
_cookiejar = http.cookiejar.CookieJar()
_opener = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(_cookiejar),
    urllib.request.HTTPRedirectHandler()
)
_opener.addheaders = [("User-Agent","PrivacyTestingValidator/1.1")]

def _read_body(resp_bytes: bytes, headers: Dict[str,str]) -> str:
    ctype = headers.get("Content-Type","").lower()
    enc = "utf-8"
    if "charset=" in ctype:
        enc = ctype.split("charset=",1)[-1].split(";")[0].strip() or "utf-8"
    try:
        return resp_bytes.decode(enc, errors="replace")
    except Exception:
        return resp_bytes.decode("utf-8", errors="replace")

def get(url: str, timeout: int) -> Resp:
    history = []
    req = urllib.request.Request(url, method="GET")
    try:
        resp = _opener.open(req, timeout=timeout)
        final_url = resp.geturl()
        status = getattr(resp, "status", 200)
        headers = {k:v for k,v in resp.getheaders()}
        body = _read_body(resp.read(), headers)
        cookie_names = sorted({c.name for c in _cookiejar})
        log(f"GET {url} | final={final_url} | status={status} | redirects={0}")
        return Resp(final_url, status, headers, body, cookie_names, history)
    except urllib.error.HTTPError as e:
        headers = {k:v for k,v in (e.headers.items() if e.headers else [])}
        body = _read_body(e.read() or b"", headers)
        cookie_names = sorted({c.name for c in _cookiejar})
        log(f"GET {url} | HTTPError status={e.code}")
        return Resp(url, e.code, headers, body, cookie_names, history)
    except urllib.error.URLError as e:
        log(f"GET {url} | URLError {e}")
        return Resp(url, 0, {}, "", [], history)

def merged_headers(resp: Resp) -> Dict[str,str]:
    # stdlib can't easily expose intermediate hops; use final headers
    return resp.headers

# ---------- Helpers / rules ----------
def sev_value(name: str) -> int: return SEVERITY_ORDER.get(str(name).lower(), 2)

def collect_list(rules, key):
    vals=[]; [vals.extend(x) for x in (r.get(key) for r in rules) if isinstance(x,list)]
    seen=set(); out=[]
    for v in vals:
        s=str(v)
        if s not in seen: seen.add(s); out.append(s)
    return out

def first_reco(rules, rule_type: str, default_msg: str=""):
    for r in rules:
        if r.get("type")==rule_type and "recommendation" in r:
            return str(r["recommendation"])
    return default_msg

def load_rules(path: Path) -> List[Dict[str,Any]]:
    if not path.exists(): return []
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict): data = data.get("rules", [])
    if not isinstance(data, list): raise ValueError("rules.json must be an array")
    return data

def merge_rules(base, updates):
    ids={r.get("id") for r in base if r.get("id")}
    sigs={(r.get("type"), r.get("pattern") or r.get("header") or r.get("term") or r.get("keyword") or r.get("path")) for r in base}
    out=list(base)
    for r in updates:
        sig=(r.get("type"), r.get("pattern") or r.get("header") or r.get("term") or r.get("keyword") or r.get("path"))
        if r.get("id") in ids or sig in sigs: continue
        out.append(r); ids.add(r.get("id")); sigs.add(sig)
    return out

# ---------- Results ----------
results: Dict[str,Any] = {"total":0,"passed":0,"failed":0,"manual":0,"details":[]}
def record(name, desc, outcome, findings: Optional[Dict[str,Any]]=None):
    results["total"]+=1
    if outcome=="PASS": results["passed"]+=1
    elif outcome=="FAIL": results["failed"]+=1
    elif outcome=="MANUAL": results["manual"]+=1
    entry={"test":name,"description":desc,"result":outcome}
    if findings is not None: entry["findings"]=findings
    results["details"].append(entry)

# ---------- Parsers ----------
def parse_set_cookie(raw: str) -> List[Dict[str,Any]]:
    """
    Very light Set-Cookie parser. Not RFC-perfect but works for typical cases.
    Returns list of {name, attrs:{Secure:bool,HttpOnly:bool,SameSite:str,...}}
    """
    if not raw: return []
    # Split on comma+space boundaries between cookies (naive but acceptable for our scope)
    parts = [p.strip() for p in re.split(r',(?=[^ ;]+=)', raw)]
    cookies = []
    for p in parts:
        segs = [s.strip() for s in p.split(";")]
        if not segs or "=" not in segs[0]: continue
        name = segs[0].split("=",1)[0].strip()
        attrs = {}
        for a in segs[1:]:
            if "=" in a:
                k,v = a.split("=",1)
                attrs[k.strip().lower()] = v.strip()
            else:
                attrs[a.strip().lower()] = True
        cookies.append({"name":name, "attrs":attrs})
    return cookies

def header_contains(header_value: str, token: str) -> bool:
    return token.lower() in (header_value or "").lower()

# ---------- Core tests (existing) ----------
def test_no_pii_leakage(base_url, endpoints, pii_rules, timeout):
    desc="No PII/PHI leakage in response bodies"
    items=[]; skipped=[]
    try:
        for ep in endpoints:
            r=get(base_url+ep, timeout)
            if r.status_code!=200 or not r.text.strip():
                skipped.append({"endpoint":ep,"status":r.status_code,"len":len(r.text)}); continue
            for rule in pii_rules:
                m=re.findall(rule["pattern"], r.text)
                if m:
                    items.append({
                        "endpoint":ep,"status":r.status_code,
                        "rule_id":rule.get("id"),
                        "pii_type":rule.get("title") or rule.get("id") or "pii",
                        "count":len(m),"examples":m[:3],
                        "severity":rule.get("severity","medium"),
                        "recommendation":rule.get("recommendation")
                    })
        total=sum(i["count"] for i in items)
        record("test_no_pii_leakage", f"{desc} – {total} items",
               "PASS" if total==0 else "FAIL",
               {"items":items,"total_items":total,"skipped_non200":skipped})
    except Exception as e:
        record("test_no_pii_leakage", f"{desc} – error: {e}", "FAIL")

def test_privacy_headers_present(base_url, header_rules, timeout):
    desc="Privacy/security headers present"
    try:
        r=get(base_url+"/", timeout); hdrs=merged_headers(r)
        missing=[]
        for rule in header_rules:
            h=rule["header"]
            if h not in hdrs:
                missing.append({"rule_id":rule.get("id"),"header":h,
                                "severity":rule.get("severity","medium"),
                                "recommendation":rule.get("recommendation")})
        record("test_privacy_headers_present", desc,
               "PASS" if not missing else "FAIL",
               {"missing":missing,"missing_count":len(missing),"status":r.status_code})
    except Exception as e:
        record("test_privacy_headers_present", f"{desc} – error: {e}", "FAIL")

def test_no_tracking_cookies_before_consent(base_url, timeout, rules):
    desc="No cookies before consent"
    try:
        r=get(base_url+"/", timeout)
        raw = r.headers.get("Set-Cookie","")
        parsed_from_header = [c["name"] for c in parse_set_cookie(raw)]
        all_seen = sorted(set(r.cookies) | set(parsed_from_header))
        record("test_no_tracking_cookies_before_consent", desc,
               "PASS" if not all_seen else "FAIL",
               {"cookies_count":len(all_seen),"cookies":all_seen[:10],
                "raw_set_cookie_present":bool(raw),"status":r.status_code,
                "recommendation":first_reco(rules,"cookie_before_consent","Require consent before setting cookies.")})
    except Exception as e:
        record("test_no_tracking_cookies_before_consent", f"{desc} – error: {e}", "FAIL")

def test_form_does_not_request_excessive_data(base_url, form_paths, form_rules, timeout):
    desc="Signup forms avoid over-collection"
    try:
        bad=[]
        for path in form_paths:
            r=get(base_url+path, timeout); html=r.text.lower()
            for rule in form_rules:
                term=str(rule["term"]).lower()
                if term and term in html:
                    bad.append({"path":path,"term":term,
                                "rule_id":rule.get("id"),
                                "severity":rule.get("severity","medium"),
                                "recommendation":rule.get("recommendation")})
        record("test_form_does_not_request_excessive_data", desc,
               "PASS" if not bad else "FAIL",
               {"bad_fields":bad,"bad_fields_count":len(bad)})
    except Exception as e:
        record("test_form_does_not_request_excessive_data", f"{desc} – error: {e}", "FAIL")

def test_right_to_erasure_stub(rules):
    desc="Right-to-erasure / retention workflow (manual)"
    record("test_right_to_erasure_stub", desc, "MANUAL",
           {"manual_check_required":True,
            "recommendation":first_reco(rules,"erasure_manual","Verify delete/export request workflow")})

def test_privacy_settings_accessible(base_url, paths, timeout):
    desc="Privacy settings/info accessible"
    try:
        found=[]; checked=[]
        for p in paths:
            r=get(base_url+p, timeout); checked.append({"path":p,"status":r.status_code})
            if r.status_code==200 and any(h in r.text.lower() for h in PRIVACY_HINTS):
                found.append(p)
        record("test_privacy_settings_accessible", desc,
               "PASS" if found else "FAIL",
               {"accessible_paths":found,"checked":checked,"count":len(found)})
    except Exception as e:
        record("test_privacy_settings_accessible", f"{desc} – error: {e}", "FAIL")

def test_https_required(base_url, require_https: bool):
    desc="HTTPS enforced for tested base URL"
    if not require_https:
        record("test_https_required", desc+" (disabled by rules)", "PASS", {"url":base_url}); return
    record("test_https_required", desc, "PASS" if base_url.lower().startswith("https") else "FAIL", {"url":base_url})

def test_opt_out_mechanism_exists(base_url, opt_rules, timeout):
    desc="Opt-out/unsubscribe mechanism visible"
    try:
        r=get(base_url+"/", timeout); txt=r.text.lower(); hits=[]
        for rule in opt_rules:
            kw=str(rule["keyword"]).lower()
            if kw and kw in txt:
                hits.append({"rule_id":rule.get("id"),"keyword":kw,
                             "severity":rule.get("severity","low"),
                             "recommendation":rule.get("recommendation")})
        record("test_opt_out_mechanism_exists", desc, "PASS" if hits else "FAIL",
               {"keywords_found":hits,"count":len(hits)})
    except Exception as e:
        record("test_opt_out_mechanism_exists", f"{desc} – error: {e}", "FAIL")

def test_no_stack_trace_or_debug_output(base_url, debug_rules, timeout):
    desc="No debug/stack trace in error responses"
    try:
        r=get(base_url+"/nonexistent-route", timeout); txt=r.text.lower(); leaks=[]
        for rule in debug_rules:
            term=str(rule["term"]).lower()
            if term and term in txt:
                leaks.append({"rule_id":rule.get("id"),"term":term,
                              "severity":rule.get("severity","medium"),
                              "recommendation":rule.get("recommendation")})
        record("test_no_stack_trace_or_debug_output", desc, "PASS" if not leaks else "FAIL",
               {"leaks":leaks,"count":len(leaks)})
    except Exception as e:
        record("test_no_stack_trace_or_debug_output", f"{desc} – error: {e}", "FAIL")

def test_breach_notification_policy_linked(base_url, breach_rules, timeout):
    desc="Breach notification policy visible"
    try:
        r=get(base_url+"/privacy", timeout); txt=r.text.lower(); mentions=[]
        for rule in breach_rules:
            kw=str(rule["keyword"]).lower()
            if not kw: continue
            c=txt.count(kw)
            if c>0: mentions.append({"rule_id":rule.get("id"),"keyword":kw,"count":c,
                                     "severity":rule.get("severity","low"),
                                     "recommendation":rule.get("recommendation")})
        record("test_breach_notification_policy_linked", desc, "PASS" if mentions else "FAIL",
               {"mentions":mentions,"mentions_total":sum(m['count'] for m in mentions)})
    except Exception as e:
        record("test_breach_notification_policy_linked", f"{desc} – error: {e}", "FAIL")

# ---------- NEW Tests ("Plus" coverage) ----------
def test_cookie_attribute_hygiene(base_url, rules, timeout):
    """
    Check Secure/HttpOnly/SameSite flags on session-like cookies.
    Rules:
      type: cookie_flag
      name_pattern: "session|sid|auth"
      require_secure: true
      require_httponly: true
      require_samesite: "Lax" (or "Strict"/"Any")
    """
    desc="Cookie attribute hygiene (Secure/HttpOnly/SameSite)"
    try:
        r=get(base_url+"/", timeout)
        ck = parse_set_cookie(r.headers.get("Set-Cookie",""))
        name_regex = None
        req_secure=req_http=None
        req_samesite=None
        sev="medium"; reco=None
        for rule in rules:
            if rule.get("type")=="cookie_flag":
                name_regex = re.compile(rule.get("name_pattern","session|sid|auth"), re.I)
                req_secure = bool(rule.get("require_secure", True))
                req_http   = bool(rule.get("require_httponly", True))
                req_samesite = str(rule.get("require_samesite","Lax")).lower()
                sev = rule.get("severity","high")
                reco = rule.get("recommendation","Mark session cookies Secure, HttpOnly, and SameSite=Lax/Strict.")
                break
        if name_regex is None:
            record("test_cookie_attribute_hygiene", desc+" (no rule)", "PASS", {"checked":0}); return

        findings=[]
        for c in ck:
            if not name_regex.search(c["name"]):
                continue
            attrs = {k.lower():v for k,v in c["attrs"].items()}
            missing=[]
            if req_secure and "secure" not in attrs: missing.append("Secure")
            if req_http and "httponly" not in attrs: missing.append("HttpOnly")
            if req_samesite and req_samesite!="any":
                ss = str(attrs.get("samesite","")).lower()
                if ss not in ("lax","strict") or (req_samesite in ("lax","strict") and ss!=req_samesite):
                    missing.append(f"SameSite({req_samesite})")
            if missing:
                findings.append({"cookie":c["name"], "missing":missing, "severity":sev, "recommendation":reco})
        outcome = "PASS" if not findings else "FAIL"
        record("test_cookie_attribute_hygiene", desc, outcome,
               {"checked": len([c for c in ck if name_regex.search(c["name"])]),
                "non_compliant": len(findings), "details": findings})
    except Exception as e:
        record("test_cookie_attribute_hygiene", f"{desc} – error: {e}", "FAIL")

def test_no_store_on_sensitive_paths(base_url, rules, timeout):
    """
    Ensure Cache-Control: no-store (or private/no-cache) on sensitive pages.
    Rule: { "type":"no_store_paths", "paths":[...] }
    """
    desc="No-store on sensitive pages"
    try:
        paths=[]
        severity="medium"; reco="Set Cache-Control: no-store (and Pragma: no-cache) on sensitive pages."
        for r in rules:
            if r.get("type")=="no_store_paths":
                paths.extend(r.get("paths",[]))
                severity = r.get("severity","medium")
                reco = r.get("recommendation", reco)
        if not paths:
            record("test_no_store_on_sensitive_paths", desc+" (no paths)", "PASS", {"checked":0}); return

        bad=[]
        for p in paths:
            resp=get(base_url+p, timeout)
            cc = resp.headers.get("Cache-Control","")
            pragma = resp.headers.get("Pragma","")
            # acceptable if contains 'no-store' OR (private and no-cache)
            ok = ("no-store" in cc.lower()) or ("private" in cc.lower() and "no-cache" in cc.lower())
            if not ok:
                bad.append({"path":p,"status":resp.status_code,
                           "severity":severity,"recommendation":reco,"cache_control":cc,"pragma":pragma})
        outcome="PASS" if not bad else "FAIL"
        record("test_no_store_on_sensitive_paths", desc, outcome,
               {"checked":len(paths),"non_compliant":len(bad),"details":bad})
    except Exception as e:
        record("test_no_store_on_sensitive_paths", f"{desc} – error: {e}", "FAIL")

def test_cors_policy_sanity(base_url, timeout):
    """
    Fail if ACAO: * with credentials or wildcard on root page.
    """
    desc="CORS policy sanity"
    try:
        r=get(base_url+"/", timeout)
        acao = r.headers.get("Access-Control-Allow-Origin","")
        acc  = r.headers.get("Access-Control-Allow-Credentials","").lower()
        issues=[]
        if acao.strip() == "*":
            issues.append("ACAO:* on root")
            if acc in ("true","1"):
                issues.append("credentials enabled with ACAO:*")
        outcome="PASS" if not issues else "FAIL"
        record("test_cors_policy_sanity", desc, outcome,
               {"issues":issues,"acao":acao,"allow_credentials":acc})
    except Exception as e:
        record("test_cors_policy_sanity", f"{desc} – error: {e}", "FAIL")

def test_csrf_token_hint(base_url, rules, timeout, fallback_paths: List[str]):
    """
    Look for hidden CSRF token inputs on form pages.
    Rule: { "type":"csrf_hint", "form_paths":[...] }
    """
    desc="CSRF token hint on forms"
    try:
        paths=[]
        severity="medium"; reco="Include hidden anti-CSRF token field on forms."
        for r in rules:
            if r.get("type")=="csrf_hint":
                paths.extend(r.get("form_paths",[]))
                severity = r.get("severity","medium")
                reco = r.get("recommendation", reco)
        if not paths:
            paths = fallback_paths

        pattern = re.compile(r'<input[^>]*(type=["\']hidden["\'])[^>]*name=["\'](csrf|_csrf|xsrf|_token)["\']', re.I)
        missing=[]
        checked=0
        for p in paths:
            resp=get(base_url+p, timeout)
            if resp.status_code!=200: continue
            checked+=1
            if not pattern.search(resp.text):
                missing.append({"path":p,"severity":severity,"recommendation":reco})
        outcome="PASS" if not missing else "FAIL"
        record("test_csrf_token_hint", desc, outcome,
               {"checked":checked,"missing":len(missing),"details":missing})
    except Exception as e:
        record("test_csrf_token_hint", f"{desc} – error: {e}", "FAIL")

def test_server_fingerprint_minimized(base_url, rules, timeout):
    """
    Forbid software/version-identifying headers.
    Rule: { "id":"server_fingerprint","type":"header_forbid","headers":[...] }
    """
    desc="Server fingerprint minimized"
    try:
        forbid = []
        sev="low"; reco="Remove identifying headers like Server/X-Powered-By."
        for r in rules:
            if r.get("type")=="header_forbid":
                forbid = [h.lower() for h in r.get("headers",[])]
                sev = r.get("severity","low")
                reco = r.get("recommendation", reco)
                break
        if not forbid:
            record("test_server_fingerprint_minimized", desc+" (no rule)", "PASS", {"checked":0}); return

        resp = get(base_url+"/", timeout)
        present=[]
        for h in forbid:
            for k,v in resp.headers.items():
                if k.lower()==h and v:
                    present.append({"header":k,"value":v,"severity":sev,"recommendation":reco})
        outcome="PASS" if not present else "FAIL"
        record("test_server_fingerprint_minimized", desc, outcome,
               {"present_count":len(present),"details":present})
    except Exception as e:
        record("test_server_fingerprint_minimized", f"{desc} – error: {e}", "FAIL")

# ---------- Runner / outputs ----------
def run_tests(base_url, rules, timeout):
    endpoints = collect_list(rules,"endpoints") or DEFAULT_ENDPOINTS
    form_paths = collect_list(rules,"form_paths") or DEFAULT_FORM_PATHS
    privacy_paths = [r.get("path") for r in rules if r.get("type")=="privacy_path"] or DEFAULT_PRIVACY_CANDIDATES

    pii_rules        = [r for r in rules if r.get("type")=="pii"               and r.get("pattern")]
    header_rules     = [r for r in rules if r.get("type")=="header"            and r.get("header")]
    form_forbid      = [r for r in rules if r.get("type")=="form_forbid"       and r.get("term")]
    optout_rules     = [r for r in rules if r.get("type")=="opt_out_keyword"   and r.get("keyword")]
    debug_rules      = [r for r in rules if r.get("type")=="debug_term"        and r.get("term")]
    breach_rules     = [r for r in rules if r.get("type")=="breach_keyword"    and r.get("keyword")]
    require_https=True
    for r in rules:
        if r.get("type")=="require_https": require_https=bool(r.get("enabled",True))

    # Baseline
    test_no_pii_leakage(base_url, endpoints, pii_rules, timeout)
    test_privacy_headers_present(base_url, header_rules, timeout)
    test_no_tracking_cookies_before_consent(base_url, timeout, rules)
    test_form_does_not_request_excessive_data(base_url, form_paths, form_forbid, timeout)
    test_right_to_erasure_stub(rules)
    test_privacy_settings_accessible(base_url, privacy_paths, timeout)
    test_https_required(base_url, require_https)
    test_opt_out_mechanism_exists(base_url, optout_rules, timeout)
    test_no_stack_trace_or_debug_output(base_url, debug_rules, timeout)
    test_breach_notification_policy_linked(base_url, breach_rules, timeout)

    # Plus
    test_cookie_attribute_hygiene(base_url, rules, timeout)
    test_no_store_on_sensitive_paths(base_url, rules, timeout)
    test_cors_policy_sanity(base_url, timeout)
    test_csrf_token_hint(base_url, rules, timeout, fallback_paths=form_paths)
    test_server_fingerprint_minimized(base_url, rules, timeout)

def write_outputs(outdir: Path):
    results["pass_rate"] = f"{(results['passed']/results['total'])*100:.1f}%" if results["total"] else "N/A"
    (outdir/"privacy_test_results.json").write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    lines = [
        "Privacy Testing Validator – Results",
        f"Total: {results['total']}  Passed: {results['passed']}  Failed: {results['failed']}  Manual: {results['manual']}  Pass rate: {results['pass_rate']}",
        "-"*80
    ]
    for d in results["details"]:
        lines.append(f"[{d['result']}] {d['test']} – {d['description']}")
        f = d.get("findings")
        if isinstance(f, dict):
            if "total_items" in f: lines.append(f"  items: {f.get('total_items')}")
            if "missing_count" in f: lines.append(f"  missing: {f.get('missing_count')}")
            if "bad_fields_count" in f: lines.append(f"  bad_fields: {f.get('bad_fields_count')}")
            if "cookies_count" in f: lines.append(f"  cookies: {f.get('cookies_count')}")
            if "checked" in f and "non_compliant" in f: lines.append(f"  checked: {f['checked']}  non_compliant: {f['non_compliant']}")
            if "present_count" in f: lines.append(f"  present: {f['present_count']}")
            if "mentions_total" in f: lines.append(f"  mentions: {f.get('mentions_total')}")
            if "issues" in f and f["issues"]: lines.append(f"  issues: {len(f['issues'])}")
            if "skipped_non200" in f and f["skipped_non200"]:
                lines.append(f"  skipped_non200: {len(f['skipped_non200'])}")
        lines.append("")
    (outdir/"privacy_test_results.txt").write_text("\n".join(lines), encoding="utf-8")
    log(f"wrote JSON/TXT to: {outdir}")

def has_finding_at_or_above(threshold:int)->bool:
    def walk(x):
        if isinstance(x, dict):
            s=x.get("severity")
            if s is not None and SEVERITY_ORDER.get(str(s).lower(),2)>=threshold: return True
            return any(walk(v) for v in x.values())
        if isinstance(x, list):
            return any(walk(v) for v in x)
        return False
    return any(walk(d.get("findings",{})) for d in results["details"])

# ---------- CLI ----------
def parse_args():
    p=argparse.ArgumentParser(description="Privacy Testing Validator (lean, stdlib)")
    p.add_argument("--rules", required=True)
    p.add_argument("--update-rules")
    p.add_argument("--outdir", default="out")
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    p.add_argument("--base-url", default=os.getenv("PRIVACY_TEST_BASE_URL"))
    p.add_argument("--fail-on-find", action="store_true")
    p.add_argument("--min-severity", default="medium", choices=list(SEVERITY_ORDER.keys()))
    return p.parse_args()

def main():
    args=parse_args()
    base=args.base_url or os.getenv("PRIVACY_TEST_BASE_URL") or "http://localhost:5000"
    outdir=Path(args.outdir); outdir.mkdir(parents=True, exist_ok=True)
    log_init(outdir)

    rules=load_rules(Path(args.rules))
    if args.update_rules:
        rules=merge_rules(rules, load_rules(Path(args.update_rules)))
        Path(args.rules).write_text(json.dumps(rules, indent=2, ensure_ascii=False), encoding="utf-8")
        log("rules.json updated")

    run_tests(base, rules, args.timeout)
    write_outputs(outdir)

    if args.fail_on_find and has_finding_at_or_above(SEVERITY_ORDER[args.min_severity]):
        log(f"Failing due to findings ≥ {args.min_severity}")
        if log_file: log_file.close()
        sys.exit(1)

    if log_file: log_file.close()
    print("Done...!")

if __name__ == "__main__":
    main()

