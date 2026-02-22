#!/usr/bin/env python3

import argparse
import base64
import hashlib
import os
import sys
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def derive_key(password: str) -> bytes:
    return hashlib.sha256(password.encode("utf-8")).digest()


def encrypt(data: bytes, password: str) -> bytes:
    aesgcm = AESGCM(derive_key(password))
    iv = os.urandom(12)
    return base64.b64encode(iv + aesgcm.encrypt(iv, data, None))


def decrypt(b64_data: bytes, password: str) -> bytes:
    try:
        raw = base64.b64decode(b64_data)
        return AESGCM(derive_key(password)).decrypt(raw[:12], raw[12:], None)
    except Exception:
        raise ValueError("密码错误或数据已损坏")


def resolve_password(arg_pwd: str) -> str:
    pwd = os.environ.get("PASSWORD")
    if not pwd and Path(".env").is_file():
        for line in Path(".env").read_text(encoding="utf-8").splitlines():
            if line.startswith("PASSWORD="):
                pwd = line.split("=", 1)[1].strip()
                break
    pwd = pwd or arg_pwd
    if not pwd:
        sys.stderr.write(
            "未提供密码，请通过 PASSWORD 环境变量、.env 文件 or -p 参数指定\n"
        )
        sys.exit(1)
    return pwd


def process_file(
    filepath: Path, is_decrypt: bool, pwd: str, outpath=None, overwrite=False
):
    try:
        data = filepath.read_bytes()
        res = decrypt(data, pwd) if is_decrypt else encrypt(data, pwd)

        if outpath is None:
            if is_decrypt:
                try:
                    sys.stdout.write(res.decode("utf-8") + "\n")
                except UnicodeDecodeError:
                    sys.stdout.buffer.write(res)
            else:
                sys.stdout.write(res.decode("ascii") + "\n")
            return

        if isinstance(outpath, str):
            out = Path(outpath)
        else:
            if is_decrypt:
                out = (
                    filepath.with_name(filepath.name[:-4])
                    if filepath.name.endswith(".dec")
                    else filepath
                )
            else:
                out = filepath.with_name(f"{filepath.name}.dec")

        if out.exists() and not overwrite:
            sys.stderr.write(f"目标文件 '{out}' 已存在，为保护数据已取消操作\n")
            sys.exit(1)

        out.write_bytes(res)
        print(out)
    except Exception as e:
        sys.stderr.write(f"{filepath}: {e}\n")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(add_help=False, description="极简 AES-GCM 工具")
    parser.add_argument("filepath", nargs="?", type=str, help="要处理的文件")
    parser.add_argument("-d", "--decrypt", action="store_true", help="解密模式")
    parser.add_argument("-t", "--text", type=str, help="直接处理传入的文本内容")
    parser.add_argument(
        "-f", "--file", type=str, help="处理指定路径的文件 (同位置参数)"
    )
    parser.add_argument(
        "-o",
        "--out",
        nargs="?",
        const=True,
        help="将结果输出到文件 (不指定文件名则自动去除或加入 .dec 后缀)",
    )
    parser.add_argument(
        "-O",
        "--overwrite-out",
        nargs="?",
        const=True,
        help="将结果输出到文件 (不指定文件名则自动去除或加入 .dec 后缀, 不检查覆盖)",
    )
    parser.add_argument(
        "-p", "--password", type=str, help="指定密码 (优先于环境变量及.env)"
    )
    parser.add_argument("-h", "--help", action="help", help="显示此帮助信息并退出")

    args = parser.parse_args()

    target_file = args.file or args.filepath

    if not args.text and not target_file:
        parser.print_help()
        sys.exit(0)

    pwd = resolve_password(args.password)

    out_val = args.overwrite_out if args.overwrite_out is not None else args.out
    should_overwrite = args.overwrite_out is not None

    if args.text:
        data = args.text.encode("utf-8" if not args.decrypt else "ascii")
        try:
            res = decrypt(data, pwd) if args.decrypt else encrypt(data, pwd)
            if isinstance(out_val, str):
                out_path = Path(out_val)
                if out_path.exists() and not should_overwrite:
                    sys.stderr.write(
                        f"目标文件 '{out_path}' 已存在，为保护数据已取消操作\n"
                    )
                    sys.exit(1)
                out_path.write_bytes(res)
                print(out_path)
            else:
                if args.decrypt:
                    try:
                        sys.stdout.write(res.decode("utf-8") + "\n")
                    except UnicodeDecodeError:
                        sys.stdout.buffer.write(res)
                else:
                    sys.stdout.write(res.decode("ascii") + "\n")
        except Exception as e:
            sys.stderr.write(f"{e}\n")
            sys.exit(1)
        return

    target = Path(target_file)
    if not target.is_file():
        sys.stderr.write(f"找不到文件 '{target}'\n")
        sys.exit(1)

    process_file(target, args.decrypt, pwd, out_val, should_overwrite)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)

