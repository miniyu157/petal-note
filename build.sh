#!/bin/bash

readonly REPO="https://raw.githubusercontent.com/miniyu157/petal-note/main"

printf "从 miniyu157/petal-note 拉取 index.html 到 public/ ...\n"
curl -sSL "$REPO/index.html" -o "public/index.html"

TARGET_FILE=$(python3 -c '
import sys, tomllib
from pathlib import Path
try:
    with open("public/config.toml", "rb") as f:
        src = tomllib.load(f).get("private_source", "")
        if src:
            print(Path(src).name)
except Exception:
    pass
')

if [[ -n $TARGET_FILE ]]; then
    if [[ -f $TARGET_FILE ]]; then
        printf "从 miniyu157/petal-note 拉取 cipher-thoughts.py ...\n"
        curl -sSL "$REPO/cipher-thoughts.py" -o "cipher-thoughts.py"

        pip install -q cryptography

        python3 cipher-thoughts.py -f "$TARGET_FILE" -O "public/$TARGET_FILE" 2>&1 |
            sed 's/^/[cipher-thoughts.py] /'
    else
        printf "找不到文件: %s\n" "$TARGET_FILE"
    fi
else
    printf "跳过 private_source\n"
fi
