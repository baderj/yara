import argparse


def run(path: str, prefix: str = "string", wide: bool = False):
    nr = 0
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            w = " wide" if wide else ""
            line = line.replace('"', "\\\"")
            pattern = f'${prefix}_{nr} = "{line}"{w}'
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
