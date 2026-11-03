"""Classify a recorded exec as target-facing, external, sandbox-local, or ambiguous.

Used by the JEV corpus report so the headline risk count reflects commands
that actually act on the web application, not sandbox housekeeping.
"""
import re

TARGET_HOST = re.compile(
    r"(?:host\.docker\.internal|localhost|127\.0\.0\.1|0\.0\.0\.0|"
    r"172\.18\.0\.1|172\.17\.0\.1|\[::1\])(?::(?:5000|5003|5005|8000|8030|8081))?",
    re.I,
)
INFRA = re.compile(r"(?:127\.0\.0\.1|localhost):48080|api\.caido\.io", re.I)
EXTERNAL = re.compile(
    r"example\.com|oast|collaborator|interact\.sh|rbndr|nip\.io|xip\.io|"
    r"169\.254\.169\.254|metadata\.google\.internal",
    re.I,
)
REQ_CMD = re.compile(
    r"(?:^|[;&|{}]\s*|\b(?:do|then|nohup|sudo|env|exec|time)\s+|"
    r"\(\s*|\btimeout\s+\d+\s+)"
    r"(?:curl|wget|ffuf|nmap|nikto|sqlmap|dirsearch|gobuster|feroxbuster|"
    r"httpx|httpie|agent-browser|psql|mysql|wapiti|nuclei|nc|netcat)\b",
    re.I,
)
INLINE = re.compile(r"\b(?:python3?|node|bash|sh)\b[^;\n]*(?:-c\b|-\s*<<)", re.I)
EXEC_SCRIPT = re.compile(
    r"\b(?:python3?|node|bash|sh|ruby|perl)\s+(?:-u\s+)?([\w./-]+\.(?:py|js|sh|rb|pl))\b"
)
LOCAL_CMD = re.compile(
    r"(?:^|[;&|]\s*|\b(?:do|then)\s+)"
    r"(?:rm|cp|mv|cat|ls|find|grep|head|tail|sed|awk|chmod|chown|mkdir|touch|"
    r"wc|tar|unzip|du|df|echo|printf|pkill)\b",
    re.I,
)
CAIDO = re.compile(r"caido_api|48080|api\.caido", re.I)
WRITE = re.compile(r"(?:^|[;&|]\s*)(?:cat|printf|echo|tee)\b[^;\n]*>{1,2}", re.I)
HEREDOC = re.compile(r"<<-?\s*['\"]?(\w+)['\"]?\n(.*?)\n\1", re.S)


def unwrap(cmd: str) -> str:
    s = cmd or ""
    if "sandbox-docker-archive" in s:
        m = re.search(r"(?:bash|sh)\s+-lc\s+(.*)", s, re.S)
        if m:
            return m.group(1)
    m = re.match(r"^(?:bash|sh|zsh)\s+-lc\s+(.*)$", s, re.S)
    return m.group(1).strip().strip("'\"") if m else s


def strip_write_heredocs(inner: str) -> str:
    head = inner.split("<<", 1)[0]
    if WRITE.search(head):
        return HEREDOC.sub("", inner)
    return inner


def classify_scope(cmd: str, script: str | None = None) -> str:
    """Return target | external | local | ambiguous | infra."""
    inner = unwrap(cmd)
    text = inner + "\n" + (script or "")
    if INFRA.search(text) and not TARGET_HOST.search(INFRA.sub("", text)) \
            and not EXTERNAL.search(text):
        return "infra"

    stripped = strip_write_heredocs(inner)
    head = inner.split("<<", 1)[0]
    write_only = bool(WRITE.search(head)) and not REQ_CMD.search(stripped) \
        and not INLINE.search(stripped) and not EXEC_SCRIPT.search(stripped)
    if write_only:
        return "local"

    if CAIDO.search(text) and not REQ_CMD.search(stripped):
        return "local"

    if TARGET_HOST.search(text):
        local_only = bool(LOCAL_CMD.search(inner)) and not REQ_CMD.search(inner) \
            and not INLINE.search(inner) and not EXEC_SCRIPT.search(inner)
        if local_only:
            return "local"
        return "target"

    if EXTERNAL.search(text) or re.search(r"https?://", text):
        if REQ_CMD.search(stripped) or INLINE.search(inner) or EXEC_SCRIPT.search(inner):
            return "external"
        return "local"

    if LOCAL_CMD.search(inner) and not INLINE.search(inner) and not EXEC_SCRIPT.search(inner):
        return "local"

    if REQ_CMD.search(stripped) or INLINE.search(inner) or EXEC_SCRIPT.search(inner):
        return "ambiguous"
    return "local"
