import argparse
import re
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

import plyara

nr_of_errors = 0


class Level(Enum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


YARA_EXTENSIONS = [".yara", ".yar"]


def parse_rule(path: Path):
    with open(path) as r:
        data = r.read()
    yara_parser = plyara.Plyara()
    try:
        return yara_parser.parse_string(data)
    except plyara.exceptions.ParseTypeError as e:
        log(path=path, msg=f"can't parse: {e}")
        return


def validate_empty_lines(path: Path, **_):
    def is_empty(line):
        return re.match(r"^\s*$", line)

    with open(path) as r:
        lines = r.readlines()
    for nr, line in enumerate(lines):
        lnnr = nr + 1
        if line.startswith("rule"):
            if not is_empty(lines[nr + 1]):
                log(path=path, line=lnnr + 1, msg="missing empty line after rule start")
            if nr and not is_empty(lines[nr - 1]):
                log(
                    path=path, line=lnnr + 1, msg="missing empty line before rule start"
                )
        if is_empty(line):
            if nr + 1 == len(lines):
                log(path=path, line=lnnr, msg="empty line at end of rule")
            elif nr == 0:
                log(path=path, line=1, msg="file starts with empty line")
            elif is_empty(lines[nr + 1]):
                log(path=path, line=lnnr, msg="two empty lines")
        for block in ["meta", "strings", "condition"]:
            if re.match(fr"^\s*{block}:", line):
                if not is_empty(lines[nr - 1]):
                    log(path=path, line=lnnr, msg=f"missing newline before {block}")
        if line.strip() == "}":
            if is_empty(lines[nr - 1]):
                log(path=path, line=lnnr - 1, msg="empty line before end of rule block")


def validate_indents(path: Path, **_):
    with open(path) as r:
        for nr, line in enumerate(r):
            m = re.match("( *)\t", line)
            if m:
                col = len(m.group(1)) + 1
                log(path=path, msg="uses tab to indent", line=nr + 1, col=col)

            m = re.match("( *)", line)
            if len(m.group(1)) % 4:
                log(path=path, msg="not using 4 spaces to indent", line=nr + 1)


def validate_name(rule: Dict[str, Any], **_) -> Optional[str]:
    name = rule["rule_name"]
    m = re.match("^[a-z0-9_]+$", name)
    if not m:
        return f"invalid rule name: {name}"


def validate_meta(rule: Dict[str, Any], **_) -> List[str]:
    FIELDS = {
        "author": "Johannes Bader @viql",
        "tlp": "TLP:WHITE",
        "date": None,
        "description": None,
        "version": None,
    }
    res = []
    tmp = rule["metadata"]
    meta = {}
    for entry in tmp:
        k, v = list(entry.items())[0]
        if k in meta:
            res.append(f"duplicate meta key: '{k}'")
        meta[k] = v

    for key, value in FIELDS.items():
        if not meta.get(key):
            res.append(f"'{key}' not set")
        elif value and meta.get(key) != value:
            res.append(f"'{key}' set to '{meta.get(key)}' instead of '{value}'")

    if "date" in meta:
        try:
            datetime.strptime(meta.get("date"), "%Y-%m-%d")
        except Exception as e:
            res.append(f"invalid date: {e}")
    if "version" in meta:
        v = meta["version"]
        m = re.match(r"^v\d\.\d+$", v)
        if not m:
            res.append(f"invalid version: '{v}")

    return res


def check_yara_rule(path: Path):
    rules = parse_rule(path)
    if rules is None:
        return
    if len(rules) == 0:
        log(path=path, msg="contains no rules")
        return
    validators = [validate_meta, validate_name, validate_indents, validate_empty_lines]

    for rule in rules:
        for func in validators:
            try:
                errors = func(rule=rule, path=path)
                if errors:
                    if isinstance(errors, str):
                        log(path=path, msg=errors)
                    else:
                        for error in errors:
                            log(path=path, msg=error)
            except Exception as e:
                log(path, msg=f"failed to run {func}: {e}")


def check_file(path: Path):
    if path.suffix in YARA_EXTENSIONS:
        check_yara_rule(path)


def check_path(path: Path, recursive: bool = False):
    if path.is_file():
        check_file(path)
    elif path.is_dir():
        for f in path.glob("*"):
            if f.is_file():
                check_file(f)
            elif f.is_dir() and recursive:
                check_path(path=f, recursive=recursive)


def log(path: Path, msg: str, line: int = 1, col: int = 1, level: Level = Level.ERROR):
    if level in [Level.ERROR, Level.WARNING]:
        global nr_of_errors
        nr_of_errors += 1
    print(f"{path.resolve()}:{line}:{col}:{level.value}:{msg}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="linter for the yara rules")
    parser.add_argument(
        "path", help="path to directory of yara files or single yara file"
    )
    parser.add_argument(
        "-r", "--recursive", help="recursively scan directory", action="store_true"
    )
    args = parser.parse_args()
    check_path(path=Path(args.path), recursive=args.recursive)
    if nr_of_errors:
        exit(1)
