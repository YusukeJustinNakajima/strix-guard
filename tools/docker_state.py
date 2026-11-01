#!/usr/bin/env python3
# Docker状態の確認（socket直叩き）
import http.client, json, socket

class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=15)
        self.path_unix = path
    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(15)
        s.connect(self.path_unix)
        self.sock = s

def req(method, path):
    c = UnixHTTP("/var/run/docker.sock")
    c.request(method, path)
    r = c.getresponse()
    d = r.read()
    c.close()
    return r.status, d

st, ver = req("GET", "/version")
api = "/v" + json.loads(ver)["ApiVersion"] if st == 200 else "/v1.41"
print("version:", st, json.loads(ver).get("Version") if st == 200 else ver[:100])

st, d = req("GET", f"{api}/containers/json?all=1")
cs = json.loads(d) if st == 200 else []
print(f"containers(all)={len(cs)}")
for c in cs[:20]:
    names = ",".join(n.strip("/") for n in c.get("Names", []))
    ports = ",".join(f"{p.get('PublicPort')}->{p.get('PrivatePort')}" for p in (c.get("Ports") or []) if p.get("PublicPort"))
    print(f"  [{c['State']:8s}] {names:40s} image={c['Image'][:50]:50s} ports={ports}")

st, d = req("GET", f"{api}/images/json")
imgs = json.loads(d) if st == 200 else []
print(f"\nimages={len(imgs)}")
for im in imgs[:25]:
    tag = (im.get("RepoTags") or [im["Id"][:19]])[0]
    print(f"  {tag}")
