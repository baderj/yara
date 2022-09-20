import argparse
import logging
import os
import re
import uuid
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

import colorlog

handler = colorlog.StreamHandler()
handler.setFormatter(
    colorlog.ColoredFormatter("%(log_color)s%(levelname)s: %(message)s")
)

logger = colorlog.getLogger("example")
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)


YARA_EXTENSIONS = [".yara", ".yar"]


def get_meta(path: Path):
    meta = {}
    stage = 0
    with open(path) as r:
        for line in r:
            if stage == 1:
                if not line.strip():
                    break
                key, value = line.split("=", 1)
                meta[key.strip()] = value.strip()
            elif stage == 0 and re.match(r"\s+meta:\s*$", line):
                stage = 1
    return meta


def overwrite_meta(src: Path, dst: Path, meta: Dict[str, str]):
    stage = 0
    res = []
    done = set()
    with open(src) as r:
        for line in r:
            line = line.rstrip()
            if stage != 1:
                res.append(line)
            if stage == 1:
                if not line.strip():
                    for k, v in sorted(meta.items()):
                        v = v.strip('"')
                        if k not in done:
                            res.append(8 * " " + f'{k:<25} = "{v}"')
                            done.add(k)
                    res.append("")
                    stage = 2
            elif stage == 0 and re.match(r"\s+meta:\s*$", line):
                stage = 1

    with open(dst, "w") as w:
        for i, line in enumerate(res):
            if not i:
                m = re.search("rule\s+([^ ]*)", line)
                rule_name = m.group(1)
                uid = meta["yarahub_uuid"][0:4]
                line = f"rule {rule_name}_{uid} {{"
            w.write(f"{line}\n")


def set_if_not_set(meta: Dict[str, str], k: str, v: str):
    if k not in meta:
        meta[k] = v


def map_key_to_yarahub(
    meta: Dict[str, str],
    src_key: str,
    dst_key: str,
    alert: bool = False,
    length: int = 0,
):
    for k, v in meta.items():
        v = v.strip('"')
        if k.strip().startswith(src_key) and (not length or len(v) == length):
            set_if_not_set(meta, dst_key, v)
            break
    else:
        if alert:
            msg = f"found no {src_key}, which is required, meta is:\n:{meta}"
            logger.error(msg)
            raise ValueError(msg)


def enrich_meta(meta: Dict[str, str]):
    meta["author"] = "Johannes Bader"
    if not meta["date"]:
        logger.error("missing date")
        raise ValueError("missing date")
    if not re.search(r"\d{4}-\d{2}-\d{2}", meta["date"]):
        logger.error(f"invalid date format: {meta['date']}")
        raise ValueError("invalid date")

    set_if_not_set(meta, "yarahub_author_twitter", "@viql")
    set_if_not_set(meta, "yarahub_author_email", "yara@bin.re")

    map_key_to_yarahub(meta, "hash", "yarahub_reference_md5",
                       alert=True, length=32)
    map_key_to_yarahub(meta, "reference", "yarahub_reference_link")

    set_if_not_set(meta, "yarahub_uuid", str(uuid.uuid4()))
    set_if_not_set(meta, "yarahub_license", "CC BY-SA 4.0")
    set_if_not_set(meta, "yarahub_rule_matching_tlp", "TLP:WHITE")
    set_if_not_set(meta, "yarahub_rule_sharing_tlp", "TLP:WHITE")


def parse_rule(src: Path, dst: Path):
    meta = get_meta(src)
    try:
        enrich_meta(meta)
    except ValueError:
        return
    base = os.path.dirname(dst)
    if base and not os.path.isdir(base):
        os.makedirs(base)
    overwrite_meta(src, dst, meta)


def convert_file(src: Path, dst: Path, root: Optional[Path] = None):
    if src.suffix not in YARA_EXTENSIONS:
        return
    if root:
        rel_path = src.relative_to(root)
        dst_path = dst / rel_path
    else:
        dst_path = dst
    logger.info(dst_path)

    parse_rule(src, dst_path)


def check_path(
    src: Path, dst: Path, recursive: bool = False, root: Optional[Path] = None
):
    if not root:
        root = src
    if src.is_file():
        convert_file(src, dst)
    elif src.is_dir():
        for f in src.glob("*"):
            if f.is_file():
                convert_file(src=f, dst=dst, root=root)
            elif f.is_dir() and recursive:
                check_path(src=f, dst=dst, recursive=recursive, root=root)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="add yarahub metadata")
    parser.add_argument(
        "src", help="path to directory of yara files or single yara file"
    )
    parser.add_argument("dst", help="output path")
    parser.add_argument(
        "-r", "--recursive", help="recursively scan directory", action="store_true"
    )
    args = parser.parse_args()
    check_path(src=Path(args.src), dst=Path(
        args.dst), recursive=args.recursive)
