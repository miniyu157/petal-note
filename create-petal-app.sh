#!/bin/bash
set -euo pipefail

readonly REPO="https://raw.githubusercontent.com/miniyu157/petal-note/main"
PATH_PART=${REPO#https://raw.githubusercontent.com/}
_user=${PATH_PART%%/*} _repo=${PATH_PART#*/} _repo=${_repo%%/*}
_src="${_user}/${_repo}"

mkdir -p "public"

printf "仓库: github.com/%s\n" "$_src"

printf "拉取 index.html...\n"
curl -fsSL "$REPO/public/index.html" -o "public/index.html"

printf "拉取 config.toml...\n"
curl -fsSL "$REPO/public/config.toml" -o "public/config.toml"

printf "\n"

cat << EOF > "public/data.txt"
Petal Note
#欢迎
欢迎使用 Petal Note! 你已经通过官方脚本初始化了一个项目。
关于如何部署和使用，请参考文档中的说明。
[点此转到仓库](https://github.com/miniyu157/petal-note?tab=readme-ov-file#-%E9%83%A8%E7%BD%B2%E4%B8%8E%E4%BD%BF%E7%94%A8)
EOF

mkdir -p "public/assets"

printf "Petal Note 初始化完成!\n"
git init -b main > /dev/null 2>&1

python3 - << 'EOF'
import http.server
import socketserver
import sys
from functools import partial
class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        pass
try:
    handler = partial(QuietHandler, directory="./public")
    with socketserver.TCPServer(("127.0.0.1", 0), handler) as httpd:
        port = httpd.server_address[1]
        print(f"已启动服务器: http://127.0.0.1:{port}/")
        httpd.serve_forever()
except KeyboardInterrupt:
    sys.exit(130)
EOF
