import argparse
import math


def run(path: str, prefix: str = "string", wide: bool = False):
    with open(path, "r") as r:
        lines = r.readlines()
    total = len(lines)
    nr = 1
    for line in lines:
        line = line.strip()
        if not line:
            continue
        w = " wide" if wide else ""
        line = line.replace("\\", "\\\\")
        line = line.replace('"', "\\\"")
        nrf = str(nr).zfill(int(math.log10(total)+1))
        pattern = f'${prefix}_{nrf} = "{line}"{w}'
        print(pattern)
        nr += 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="generate yara strings from file")
    parser.add_argument("input", help="input file")
    parser.add_argument(
        "-p", "--prefix", help="string prefix", default="string")
    parser.add_argument("-w", "--wide", action="store_true",
                        help="wide strings")
    args = parser.parse_args()
    run(path=args.input, prefix=args.prefix, wide=args.wide)
