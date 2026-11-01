"""決定論的なexecポリシー検査（JEV/強モデルの判断より前に適用）。

reference_only / recon では、コマンドと解決済みスクリプト全文から
非許可HTTPメソッド・アップロード・SQL書き込み・外部egressを検出して拒否する。
full では追加検査なし（既存のPolicy Engineが担当）。
"""
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from .policy import sandbox_internal

_METHOD_FLAG = re.compile(r"(?:-X|--request)[=\s]+['\"]?([A-Za-z]+)", re.I)
_CURL_BODY = re.compile(
    r"\bcurl\b[^\n;|&]*(?:\s-d(?:\s|=)|\s--data(?:-raw|-binary|-urlencode)?(?:\s|=)"
    r"|\s-F(?:\s|=)|\s--form(?:\s|=)|\s-T(?:\s|=)|\s--upload-file(?:\s|=))", re.I)
_WGET_BODY = re.compile(r"\bwget\b[^\n;|&]*(?:--post-data|--post-file|--method=)", re.I)
_SCRIPT_METHOD = re.compile(
    r"(?:requests|httpx|axios|session|client|s)\.(post|put|patch|delete)\s*\("
    r"|\.request\(\s*['\"]([A-Za-z]+)['\"]"
    r"|method\s*[:=]\s*['\"]([A-Za-z]+)['\"]"
    r"|fetch\s*\([^)]*method\s*:\s*['\"]([A-Za-z]+)['\"]", re.I)
_HTTPIE = re.compile(r"(?<![\w-])https?\s+(POST|PUT|PATCH|DELETE)\b", re.I)
_FFUF_METHOD = re.compile(r"\bffuf\b[^\n;|&]*-X[=\s]+['\"]?([A-Za-z]+)", re.I)
_UPLOAD = re.compile(
    r"\bcurl\b[^\n;|&]*(?:\s-F(?:\s|=)|\s--form(?:\s|=)|\s-T(?:\s|=)|\s--upload-file(?:\s|=))"
    r"|multipart/form-data|\bfiles\s*=", re.I)
_SQL_WRITE = re.compile(
    r"\b(?:INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|DROP\s+TABLE|TRUNCATE\s+TABLE|ALTER\s+TABLE)\b",
    re.I)
_TOOLS = {
    "recon": re.compile(r"(?<![\w-])(sqlmap|hydra|nikto|wpscan|nuclei)(?![\w-])", re.I),
}
_ANY_URL = re.compile(r"https?://([^\s'\"<>`)`]+)", re.I)
_OAST = re.compile(r"evil\.example|oast|collaborator|interact\.sh|rbndr|nip\.io|xip\.io", re.I)
_IN_SCOPE = {"host.docker.internal", "127.0.0.1", "localhost", "0.0.0.0", "::1"}


@dataclass
class Violation:
    kind: str
    detail: str
    message: str


def detect_methods(text: str) -> set[str]:
    methods: set[str] = set()
    for m in _METHOD_FLAG.finditer(text):
        methods.add(m.group(1).upper())
    for m in _SCRIPT_METHOD.finditer(text):
        for g in m.groups():
            if g:
                methods.add(g.upper())
    for m in _HTTPIE.finditer(text):
        methods.add(m.group(1).upper())
    for m in _FFUF_METHOD.finditer(text):
        methods.add(m.group(1).upper())
    if _CURL_BODY.search(text) or _WGET_BODY.search(text):
        methods.add("POST")
    return methods


def _external_hosts(text: str, allowed: list) -> list[str]:
    allowed_l = {str(a).lower() for a in (allowed or [])}
    found = []
    for raw in _ANY_URL.findall(text):
        try:
            u = urlsplit("http://" + raw if "://" not in raw else raw)
            host = (u.hostname or "").lower()
            hostport = host + ((":" + str(u.port)) if u.port else "")
        except Exception:
            continue
        if not host:
            continue
        if host in _IN_SCOPE or host in allowed_l or hostport in allowed_l:
            continue
        if any(host == a.split(":")[0] for a in allowed_l if ":" in a):
            continue
        found.append(hostport or host)
    if _OAST.search(text):
        found.append("oast/external")
    return sorted(set(found))


def _url_hostports(text: str) -> set[str]:
    out: set[str] = set()
    for raw in _ANY_URL.findall(text):
        try:
            u = urlsplit(raw if "://" in raw else "http://" + raw)
            host = (u.hostname or "").lower()
            if host:
                out.add(host + ((":" + str(u.port)) if u.port else ""))
        except Exception:
            continue
    return out


def infra_only(cmd: str, script: str | None, policy: dict) -> bool:
    """strix自身のプロキシ等、sandboxインフラだけを対象にしたコマンドか。"""
    infra = {str(x).lower() for x in (policy.get("egress", {}).get("infra_hosts") or [])}
    if not infra:
        return False
    text = cmd + "\n" + (script or "")
    hosts = _url_hostports(text)
    return bool(hosts and not _OAST.search(text) and all(h in infra for h in hosts))


def check_exec_policy(cmd: str, script: str | None, policy: dict) -> list[Violation]:
    if sandbox_internal(cmd) or infra_only(cmd, script, policy):
        return []
    preset = policy.get("preset", "full")
    if preset == "full":
        return []
    text = cmd + "\n" + (script or "")
    allowed = {m.upper() for m in (policy.get("http", {}).get("allowed_methods") or ["GET"])}
    violations: list[Violation] = []

    bad = sorted(m for m in detect_methods(text) if m not in allowed)
    if bad:
        violations.append(Violation(
            "policy_http_method",
            ", ".join(bad),
            f"[strix-guard] {preset} policy blocks HTTP method(s): {', '.join(bad)}. "
            f"Only {', '.join(sorted(allowed))} are allowed. Do not retry this request; "
            f"use a read-only check instead."))

    if not policy.get("http", {}).get("allow_uploads", True) and _UPLOAD.search(text):
        violations.append(Violation(
            "policy_upload",
            "file upload",
            f"[strix-guard] {preset} policy blocks file uploads. Do not retry; "
            f"validate the endpoint without uploading data."))

    if not policy.get("data", {}).get("allow_writes", True) and _SQL_WRITE.search(text):
        violations.append(Violation(
            "policy_data_write",
            "SQL write",
            f"[strix-guard] {preset} policy blocks data writes. Do not retry; "
            f"use read-only queries."))

    if not policy.get("egress", {}).get("allow_external", True):
        external = _external_hosts(text, policy.get("egress", {}).get("allowed_hosts") or [])
        if external:
            violations.append(Violation(
                "policy_egress",
                ", ".join(external),
                f"[strix-guard] {preset} policy blocks external egress: {', '.join(external)}. "
                f"Only the in-scope target is allowed."))

    tool_rule = _TOOLS.get(preset)
    if tool_rule:
        m = tool_rule.search(text)
        if m:
            violations.append(Violation(
                "policy_tool",
                m.group(1),
                f"[strix-guard] {preset} policy does not allow '{m.group(1)}'. "
                f"Use passive/read-only checks."))
    return violations
