#!/bin/bash
# Apache(httpd) ターゲットを 8081 で起動し、アクセスログをファイルに出す
set -e
BASE=/home/yusuk/blackbox-testing/strix_guard/e2e_target
mkdir -p "$BASE/www" "$BASE/logs"

cat > "$BASE/www/index.html" <<'EOF'
<!DOCTYPE html><html><head><title>Acme Portal</title></head>
<body><h1>Acme Portal</h1>
<ul>
<li><a href="/allowed-1.html">Allowed 1</a></li>
<li><a href="/allowed-2.html">Allowed 2</a></li>
<li><a href="/admin/index.html">Admin</a></li>
<li><a href="/backup/backup.sql">Backup</a></li>
<li><a href="/login.html">Login</a></li>
<li><a href="/api/users.json">API Users</a></li>
</ul></body></html>
EOF
echo "allowed-1 page" > "$BASE/www/allowed-1.html"
echo "allowed-2 page" > "$BASE/www/allowed-2.html"
mkdir -p "$BASE/www/admin" "$BASE/www/backup" "$BASE/www/api"
echo "admin area" > "$BASE/www/admin/index.html"
echo "INSERT INTO users VALUES (1,'alice');" > "$BASE/www/backup/backup.sql"
echo '{"users":[{"id":1,"name":"alice"},{"id":2,"name":"bob"}]}' > "$BASE/www/api/users.json"
cat > "$BASE/www/login.html" <<'EOF'
<html><body><h1>Login</h1><form method="post" action="/login">
<input name="username"><input name="password" type="password"><button>go</button></form></body></html>
EOF

# デフォルト conf を取得してログをファイルへ
docker pull -q httpd:2.4-alpine >/dev/null
docker rm -f strixguard-target >/dev/null 2>&1 || true
docker run --rm httpd:2.4-alpine cat /usr/local/apache2/conf/httpd.conf > "$BASE/httpd.conf"
sed -i 's|/proc/self/fd/1|logs/access_log|; s|/proc/self/fd/2|logs/error_log|' "$BASE/httpd.conf"
printf '\nServerName localhost\n' >> "$BASE/httpd.conf"

docker run -d --name strixguard-target \
  -p 8081:80 \
  -v "$BASE/www":/usr/local/apache2/htdocs/:ro \
  -v "$BASE/httpd.conf":/usr/local/apache2/conf/httpd.conf:ro \
  -v "$BASE/logs":/usr/local/apache2/logs \
  httpd:2.4-alpine >/dev/null
sleep 2
echo "=== baseline GET ==="
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8081/allowed-1.html
echo "=== baseline POST (target itself allows; guard blocks later) ==="
curl -s -o /dev/null -w "%{http_code}\n" -X POST -d u=a http://127.0.0.1:8081/login
echo "=== access log ==="
cat "$BASE/logs/access_log"
