"""Host-side setup and Docker hooks for the in-container HTTP sidecar."""
import json
import os
import re
import shutil
import tempfile
import time
from urllib.parse import urlsplit

from .docker_proxy import _open_upstream

SIDECAR_DIR = "/opt/strix-guard"
LOG_DIR = "/var/log/strix-guard"
LISTEN = "127.0.0.1:48081"
UPSTREAM = "127.0.0.1:48080"


def target_hosts_from_args(strix_args: list) -> list:
    hosts = []
    for a in strix_args:
        if not re.match(r"^https?://", str(a)):
            continue
        try:
            u = urlsplit(a)
            host = (u.hostname or "").lower()
            if not host:
                continue
            port = u.port or (443 if u.scheme == "https" else 80)
            for h in (host, f"{host}:{port}"):
                if h not in hosts:
                    hosts.append(h)
        except Exception:
            continue
    if any(h.startswith("host.docker.internal") for h in hosts):
        for h in ("host.docker.internal", "127.0.0.1", "localhost"):
            if h not in hosts:
                hosts.append(h)
    return hosts


def prepare(guard_policy: dict, strix_args: list) -> dict | None:
    if not guard_policy.get("http", {}).get("enforce"):
        return None
    cache = os.path.expanduser("~/.cache")
    os.makedirs(cache, exist_ok=True)
    base = tempfile.mkdtemp(prefix="strix-guard-http-", dir=cache)
    app_dir = os.path.join(base, "app")
    log_dir = os.path.join(base, "logs")
    os.makedirs(app_dir, exist_ok=True)
    os.makedirs(log_dir, exist_ok=True)
    src = os.path.join(os.path.dirname(__file__), "http_sidecar.py")
    shutil.copy2(src, os.path.join(app_dir, "http_sidecar.py"))
    hosts = target_hosts_from_args(strix_args)
    for h in (guard_policy.get("egress", {}).get("allowed_hosts") or []):
        if str(h).lower() not in hosts:
            hosts.append(str(h).lower())
    policy = {
        "allowed_methods": guard_policy["http"].get("allowed_methods") or ["GET"],
        "allowed_hosts": hosts,
        "infra_hosts": guard_policy.get("egress", {}).get("infra_hosts") or [],
        "max_requests": guard_policy["http"].get("max_requests") or 500,
        "max_parallel": guard_policy["http"].get("max_parallel") or 10,
        "max_rps": guard_policy["http"].get("max_rps") or 10,
        "allow_connect": bool(guard_policy["http"].get("allow_connect")),
    }
    with open(os.path.join(app_dir, "policy.json"), "w", encoding="utf-8") as f:
        json.dump(policy, f, indent=2)
    os.chmod(app_dir, 0o755)
    os.chmod(os.path.join(app_dir, "http_sidecar.py"), 0o644)
    os.chmod(os.path.join(app_dir, "policy.json"), 0o644)
    os.chmod(log_dir, 0o777)
    return {"base": base, "app_dir": app_dir, "log_dir": log_dir, "policy": policy}


def _docker(upstream: tuple, method: str, path: str, body: dict | None = None) -> tuple:
    conn = _open_upstream(upstream, timeout=30)
    headers = {"Content-Type": "application/json"} if body is not None else {}
    try:
        conn.request(method, path, body=json.dumps(body).encode() if body is not None else None,
                     headers=headers)
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _api_version(upstream: tuple) -> str:
    try:
        st, data = _docker(upstream, "GET", "/version")
        if st == 200:
            return "/v" + json.loads(data).get("ApiVersion", "1.41")
    except Exception:
        pass
    return "/v1.41"


def make_hooks(sidecar: dict, upstream: tuple, audit):
    app_dir = sidecar["app_dir"]
    log_dir = sidecar["log_dir"]
    api = _api_version(upstream)

    def on_container_create(spec: dict) -> dict:
        hc = spec.setdefault("HostConfig", {})
        binds = list(hc.get("Binds") or [])
        binds.append(f"{app_dir}:{SIDECAR_DIR}:ro")
        binds.append(f"{log_dir}:{LOG_DIR}:rw")
        hc["Binds"] = binds
        env = [e for e in (spec.get("Env") or [])
               if not e.lower().startswith(("http_proxy=", "https_proxy=", "all_proxy=", "no_proxy="))]
        proxy = f"http://{LISTEN}"
        env += [f"http_proxy={proxy}", f"https_proxy={proxy}",
                f"HTTP_PROXY={proxy}", f"HTTPS_PROXY={proxy}",
                f"ALL_PROXY={proxy}", "NO_PROXY=localhost,127.0.0.1,api.caido.io"]
        spec["Env"] = env
        return spec

    def on_container_start(container_id: str):
        short = re.sub(r"[^A-Za-z0-9_.-]", "_", container_id)[:40]
        log_path = f"{LOG_DIR}/http-{short}.jsonl"
        ready_path = f"{LOG_DIR}/ready-{short}"
        cmd = ["python3", f"{SIDECAR_DIR}/http_sidecar.py",
               "--listen", LISTEN, "--upstream", UPSTREAM,
               "--policy", f"{SIDECAR_DIR}/policy.json",
               "--log", log_path, "--ready", ready_path]
        try:
            st, data = _docker(upstream, "POST", f"{api}/containers/{container_id}/exec",
                               {"Cmd": cmd, "AttachStdout": False, "AttachStderr": False,
                                "Tty": False})
            if st not in (200, 201):
                raise RuntimeError(f"exec create failed: {st} {data[:200]!r}")
            eid = json.loads(data)["Id"]
            st, data = _docker(upstream, "POST", f"{api}/exec/{eid}/start",
                               {"Detach": True, "Tty": False})
            if st not in (200, 204):
                raise RuntimeError(f"exec start failed: {st} {data[:200]!r}")
        except Exception as e:
            audit({"kind": "sidecar_error", "container_id": container_id,
                   "error": str(e)[:240]})
            return
        host_ready = os.path.join(log_dir, f"ready-{short}")
        for _ in range(100):
            if os.path.exists(host_ready):
                audit({"kind": "sidecar_started", "container_id": container_id,
                       "log": os.path.join(log_dir, f"http-{short}.jsonl")})
                return
            time.sleep(0.1)
        audit({"kind": "sidecar_error", "container_id": container_id,
               "error": "sidecar did not become ready"})

    return on_container_create, on_container_start
